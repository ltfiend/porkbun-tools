import json
import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.dnssec
import dns.rdata
import requests
import logging
import syslog
import argparse

# ------------------------
# CLI Args
# ------------------------
parser = argparse.ArgumentParser(
    description="Sync DS records for one or more domains via Porkbun API"
)
parser.add_argument(
    "domains", nargs="+", help="Domain name(s) to synchronize (e.g. example.com)"
)
args = parser.parse_args()


# ------------------------
# Configuration
# ------------------------
def load_config(path="porkbun-tools.json"):
    with open(path) as f:
        return json.load(f)


# ------------------------
# DNSKEY Handling
# ------------------------
def get_dnskey(domain, server):
    name = dns.name.from_text(domain)
    resp = dns.query.udp(
        dns.message.make_query(name, dns.rdatatype.DNSKEY), server, timeout=3
    )
    return [
        item.to_text()
        for ans in resp.answer
        if ans.rdtype == dns.rdatatype.DNSKEY
        for item in ans
    ]


def convert_dnskey(domain, dnskeys, digest_type=2):
    ds_data = []
    name = dns.name.from_text(domain)
    for txt in dnskeys:
        r = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, txt)
        if r.flags == 257:  # Only include KSK
            ds = dns.dnssec.make_ds(name, r, digest_type)
            ds_data.append(ds)
    return ds_data


# ------------------------
# Porkbun API Calls
# ------------------------
def get_existing_ds_records(domain, api_key, api_secret):
    url = f"https://api.porkbun.com/api/json/v3/dns/getDnssecRecords/{domain}"
    payload = {"apikey": api_key, "secretapikey": api_secret}
    r = requests.post(url, json=payload)
    data = r.json()
    if data.get("status") != "SUCCESS":
        print("❌ Error fetching DS records:", data)
        syslog.syslog(syslog.LOG_ERR, f"DNSSEC sync error: {data}")
        return []
    records_dict = data.get("records", {})
    if not isinstance(records_dict, dict):
        print("❌ Unexpected format for records:", records_dict)
        syslog.syslog(
            syslog.LOG_ERR, f"DNSSEC sync error: Unexpected format: {records_dict}"
        )
        return []
    records = []
    for record_id, record_data in records_dict.items():
        record_data["id"] = record_id
        records.append(record_data)
    return records


def create_dnssec_record(domain, api_key, api_secret, ds):
    url = f"https://api.porkbun.com/api/json/v3/dns/createDnssecRecord/{domain}"
    payload = {
        "apikey": api_key,
        "secretapikey": api_secret,
        "keyTag": str(ds.key_tag),
        "alg": str(ds.algorithm),
        "digestType": str(ds.digest_type),
        "digest": ds.digest.hex().upper(),
    }
    r = requests.post(url, json=payload)
    return r.json()


def delete_ds_record(domain, api_key, api_secret, record_id):
    url = f"https://api.porkbun.com/api/json/v3/dns/deleteDnssecRecord/{domain}/{record_id}"
    payload = {"apikey": api_key, "secretapikey": api_secret}
    r = requests.post(url, json=payload)
    return r.json()


# ------------------------
# Helper Functions
# ------------------------
def ds_to_tuple(ds):
    return (
        int(ds.key_tag),
        int(ds.algorithm),
        int(ds.digest_type),
        ds.digest.hex().upper(),
    )


def record_to_tuple(record):
    return (
        int(record["keyTag"]),
        int(record["alg"]),
        int(record["digestType"]),
        record["digest"].upper(),
    )


# ------------------------
# Main Sync Logic
# ------------------------
def main():
    logging.basicConfig(level=logging.INFO)
    syslog.openlog("dnssec-sync", syslog.LOG_PID, syslog.LOG_DAEMON)

    cfg = load_config()
    server = cfg["dns_server"]
    ak = cfg["api_key"]
    sk = cfg["secret_api_key"]
    dt = cfg.get("digest_type", 2)

    for domain in args.domains:
        print(f"Processing domain: {domain}")
        print(f"[+] Querying DNSKEY from {server} for {domain}...")
        keys = get_dnskey(domain, server)
        if not keys:
            msg = "❌ No DNSKEY records found."
            print(msg)
            syslog.syslog(syslog.LOG_ERR, msg)
            continue

        print("[+] Converting to DS (KSKs only)...")
        ds_local = convert_dnskey(domain, keys, dt)
        local_tuples = {ds_to_tuple(d) for d in ds_local}

        print("[+] Fetching Porkbun DS records...")
        pb_records = get_existing_ds_records(domain, ak, sk)
        remote_tuples = {record_to_tuple(r): r["id"] for r in pb_records}

        # ADD missing or confirm in sync
        for ds in ds_local:
            t = ds_to_tuple(ds)
            if t not in remote_tuples:
                msg = f"[+] Adding DS {t}"
                print(msg)
                syslog.syslog(syslog.LOG_INFO, msg)
                res = create_dnssec_record(domain, ak, sk, ds)
                print(" →", res)
            else:
                msg = f"[=] DS {t} already in sync."
                print(msg)
                syslog.syslog(syslog.LOG_INFO, msg)

        # DELETE stale
        for t, record_id in remote_tuples.items():
            if t not in local_tuples:
                msg = f"[-] Deleting stale DS {t}"
                print(msg)
                syslog.syslog(syslog.LOG_INFO, msg)
                res = delete_ds_record(domain, ak, sk, record_id)
                print(" →", res)


if __name__ == "__main__":
    main()
