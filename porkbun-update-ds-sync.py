import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.dnssec
import dns.rdata
import logging
import syslog
import argparse

from porkbun_common import load_config, get_ds_records, create_ds_record, delete_ds_record

# ------------------------
# CLI Args
# ------------------------
parser = argparse.ArgumentParser(
    description="Sync DS records for one or more domains via Porkbun API"
)
parser.add_argument(
    "-c", "--config",
    help="Path to config file (default: ~/.porkbun-tools.json)"
)
parser.add_argument(
    "-d", "--domains",
    nargs='+',
    help="Domain name(s) to synchronize (e.g. example.com example.org)"
)
args = parser.parse_args()


# ------------------------
# DNSKEY Handling
# ------------------------
def get_dnskey(domain, server):
    name = dns.name.from_text(domain)
    resp = dns.query.tcp(
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
    """Get DS records from Porkbun and format with IDs."""
    try:
        records_dict = get_ds_records(api_key, api_secret, domain)
        records = []
        for record_id, record_data in records_dict.items():
            record_data["id"] = record_id
            records.append(record_data)
        return records
    except RuntimeError as e:
        print(f"❌ Error fetching DS records: {e}")
        syslog.syslog(syslog.LOG_ERR, f"DNSSEC sync error: {e}")
        return []


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

    cfg = load_config(args.config)

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
                try:
                    res = create_ds_record(
                        ak, sk, domain,
                        ds.key_tag, ds.algorithm, ds.digest_type,
                        ds.digest.hex().upper()
                    )
                    print(" →", res)
                except RuntimeError as e:
                    print(f" → ❌ Error: {e}")
                    syslog.syslog(syslog.LOG_ERR, f"Failed to create DS: {e}")
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
                try:
                    res = delete_ds_record(ak, sk, domain, record_id)
                    print(" →", res)
                except RuntimeError as e:
                    print(f" → ❌ Error: {e}")
                    syslog.syslog(syslog.LOG_ERR, f"Failed to delete DS: {e}")


if __name__ == "__main__":
    main()
