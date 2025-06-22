#!/usr/bin/env python3
"""
Script to list Porkbun domains, nameservers, DS and DNSKEY records,
including KSK-to-DS matching alerts for mismatches.
"""

import argparse
import json
import requests
import dns.resolver
import dns.dnssec
import socket
import base64

# Base API URL
BASE_URL = "https://api.porkbun.com/api/json/v3"


def load_config(path):
    """Load API keys from config file."""
    with open(path) as f:
        return json.load(f)


def list_domains(apikey, secretapikey, start=0):
    """Retrieve domains via domain/listAll endpoint."""
    url = f"{BASE_URL}/domain/listAll"
    payload = {
        "apikey": apikey,
        "secretapikey": secretapikey,
        "start": str(start),
        "includeLabels": "no",
    }
    resp = requests.post(url, json=payload)
    data = resp.json()
    if data.get("status") != "SUCCESS":
        raise RuntimeError(f"Error listing domains: {data.get('message')}")
    return data.get("domains", [])


def get_nameservers(apikey, secretapikey, domain):
    """Retrieve NS via domain/getNs endpoint."""
    url = f"{BASE_URL}/domain/getNs/{domain}"
    payload = {"apikey": apikey, "secretapikey": secretapikey}
    resp = requests.post(url, json=payload)
    data = resp.json()
    if data.get("status") != "SUCCESS":
        raise RuntimeError(f"Error getting NS for {domain}: {data.get('message')}")
    return data.get("ns", [])


def get_ds_records(apikey, secretapikey, domain):
    """Retrieve DS records via Porkbun API."""
    url = f"{BASE_URL}/dns/getDnssecRecords/{domain}"
    payload = {"apikey": apikey, "secretapikey": secretapikey}
    resp = requests.post(url, json=payload)
    data = resp.json()
    if data.get("status") != "SUCCESS":
        raise RuntimeError(f"Error getting DS for {domain}: {data.get('message')}")
    return data.get("records", {})  # dict keyed by keyTag


def query_dnskey(domain, ns_list):
    """Query DNSKEY records, compute keyTag and return structured list."""
    resolver = dns.resolver.Resolver(configure=False)
    ips = []
    for ns in ns_list:
        try:
            ips.append(socket.gethostbyname(ns))
        except Exception:
            continue
    if ips:
        resolver.nameservers = ips
    try:
        answers = resolver.resolve(domain, "DNSKEY", lifetime=5)
        records = []
        for rdata in answers:
            key_tag = dns.dnssec.key_id(rdata)
            records.append(
                {
                    "keyTag": key_tag,
                    "flags": rdata.flags,
                    "algorithm": rdata.algorithm,
                    "key": base64.b64encode(rdata.key).decode(),
                }
            )
        return records
    except Exception as e:
        return [{"error": str(e)}]


def main():
    parser = argparse.ArgumentParser(
        description="List domains, NS, DS and DNSKEY records from Porkbun"
    )
    parser.add_argument(
        "-c", "--config", default="config.json", help="Path to config file"
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    apikey = cfg.get("api_key")
    secretapikey = cfg.get("secret_api_key")

    start = 0
    while True:
        domains = list_domains(apikey, secretapikey, start=start)
        if not domains:
            break
        for entry in domains:
            domain = entry.get("domain")
            print(f"Domain: {domain}")

            # Nameservers
            try:
                ns_list = get_nameservers(apikey, secretapikey, domain)
                print("  Nameservers:")
                for ns in ns_list:
                    print(f"    {ns}")
            except Exception as e:
                print(f"  Error retrieving NS: {e}")
                ns_list = []

            # DS Records
            print("  DS Records:")
            try:
                ds_records = get_ds_records(apikey, secretapikey, domain)
                if ds_records:
                    for rec in ds_records.values():
                        print(
                            f"    keyTag: {rec.get('keyTag')} alg: {rec.get('alg')} digestType: {rec.get('digestType')} digest: {rec.get('digest')}"
                        )
                else:
                    print("    None")
            except Exception as e:
                print(f"    Error retrieving DS: {e}")
                ds_records = {}

            # DNSKEY Records
            print("  DNSKEY Records:")
            dnskey_list = query_dnskey(domain, ns_list)
            for rec in dnskey_list:
                if "error" in rec:
                    print(f"    Error: {rec['error']}")
                else:
                    print(
                        f"    keyTag: {rec['keyTag']} flags: {rec['flags']} alg: {rec['algorithm']} key: {rec['key']}"
                    )

            # KSK-to-DS matching (flags==257)
            print("  KSK-to-DS Match Results:")
            ksk_tags = {rec["keyTag"] for rec in dnskey_list if rec.get("flags") == 257}
            ds_tags = (
                {int(rec.get("keyTag")) for rec in ds_records.values()}
                if ds_records
                else set()
            )

            # Check each KSK
            for tag in ksk_tags:
                if tag in ds_tags:
                    print(f"    keyTag {tag}: matches DS record")
                else:
                    print(f"    keyTag {tag}: MISSING DS record!")

            # Check each DS for missing KSK
            for tag in ds_tags:
                if tag not in ksk_tags:
                    print(f"    DS keyTag {tag}: NO matching DNSKEY KSK!")

            print()
        start += len(domains)


if __name__ == "__main__":
    main()

