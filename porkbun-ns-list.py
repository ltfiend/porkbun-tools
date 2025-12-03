#!/usr/bin/env python3
"""
Script to list Porkbun domains and produce a summary table of:
  - Nameservers
  - DS Key IDs
  - DNSKEY Key IDs (KSK vs ZSK)
  - Sync Status (✓ in sync, ✗ out of sync, blank if no records)
Includes a progress counter to show domains processed in real-time.
"""

import argparse
import dns.resolver
import dns.dnssec
import socket
import base64
import sys
import re

from porkbun_common import load_config, list_domains, get_nameservers, get_ds_records


def query_dnskey(domain, ns_list):
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
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Summary table of NS/DS/DNSKEY sync status with progress counter"
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to config file (default: ~/.porkbun-tools.json)"
    )
    parser.add_argument("-d", "--domain", help="work on this domain")
    args = parser.parse_args()

    cfg = load_config(args.config)
    apikey = cfg.get("api_key")
    secret = cfg.get("secret_api_key")

    rows = []
    count = 0
    start = 0
    if args.domain:
        domains = [{"domain": args.domain}]
    else:
        domains = list_domains(apikey, secret, start=start)
    for entry in domains:
        count += 1
        # Progress counter
        print(
            f"Processing entry {count} of {len(domains)}...", end="\r", file=sys.stderr
        )

        domain = entry.get("domain")
        # Nameservers
        try:
            ns = get_nameservers(apikey, secret, domain)
        except Exception:
            ns = []
        ns_str = ",".join(ns) if ns else ""

        # DS Key IDs
        try:
            ds = get_ds_records(apikey, secret, domain) or {}
        except Exception:
            ds = {}
        ds_ids = sorted(int(r.get("keyTag")) for r in ds.values()) if ds else []
        ds_str = ",".join(str(i) for i in ds_ids) if ds_ids else ""

        # DNSKEY Key IDs
        dnskeys = query_dnskey(domain, ns)
        ksk_ids = sorted(r["keyTag"] for r in dnskeys if r.get("flags") == 257)
        zsk_ids = sorted(r["keyTag"] for r in dnskeys if r.get("flags") != 257)
        parts = []
        if ksk_ids:
            parts.append("KSK:" + ",".join(str(i) for i in ksk_ids))
        if zsk_ids:
            parts.append("ZSK:" + ",".join(str(i) for i in zsk_ids))
        dnskey_str = ";".join(parts)

        # Status
        if not dnskeys and not ds_ids:
            status = ""
        else:
            ksk_set = set(ksk_ids)
            ds_set = set(ds_ids)
            status = "✓" if ksk_set == ds_set else "✗"

        rows.append((domain, ns_str, ds_str, dnskey_str, status))
    start += len(domains)

    # Print table
    headers = ("Domain", "Nameservers", "DS Key IDs", "DNSKEY Key IDs", "Status")
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    fmt = "  ".join(f"{{:{w}}}" for w in col_widths)
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in col_widths))

    doubleds = re.compile(r"\s+\d+,\d+\s+")
    doubleksk = re.compile(r"KSK\d+,\d+;")

    for i, row in enumerate(rows):
        line = fmt.format(*row)
        # Check if any field in the row is the ✗ status.
        if "✗" in row:
            # Apply light red background (101) and black text (30)
            print("\033[101m\033[30m" + line + "\033[0m")
            # Apply blue background (104) and black text (30)
        elif doubleds.search(line) or doubleksk.search(line):
            print("\033[104m\033[30m" + line + "\033[0m")
        elif i % 2 == 1:
            # Apply dark gray background (100) and black text (30)
            print("\033[100m\033[30m" + line + "\033[0m")
        else:
            print(line)

if __name__ == "__main__":
    main()
