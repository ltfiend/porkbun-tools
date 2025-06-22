#!/usr/bin/env python3
"""
Retrieve all domains from Porkbun and print their name servers.
"""

import json
import sys
import requests

CONFIG_PATH = "config.json"
API_HOST = "https://api.porkbun.com/api/json/v3"


def load_config(path=CONFIG_PATH):
    try:
        with open(path) as f:
            cfg = json.load(f)
            return cfg["api_key"], cfg["secret_api_key"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
        print(f"Error loading config ({path}): {e}", file=sys.stderr)
        sys.exit(1)


def list_domains(api_key, secret_api_key, start=0):
    """
    Call the Domain List All endpoint to fetch up to 1000 domains at a time.
    :contentReference[oaicite:0]{index=0}
    """
    url = f"{API_HOST}/domain/listAll"
    payload = {
        "apikey": api_key,
        "secretapikey": secret_api_key,
        "start": str(start),
        "includeLabels": "no",
    }
    resp = requests.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "SUCCESS":
        raise RuntimeError(f"API error listing domains: {data}")
    return data.get("domains", [])


def get_nameservers(api_key, secret_api_key, domain):
    """
    Call the Domain Get Name Servers endpoint for a given domain.
    :contentReference[oaicite:1]{index=1}
    """
    url = f"{API_HOST}/domain/getNs/{domain}"
    payload = {"apikey": api_key, "secretapikey": secret_api_key}
    resp = requests.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "SUCCESS":
        raise RuntimeError(f"API error getting NS for {domain}: {data}")
    return data.get("ns", [])


def main():
    api_key, secret_api_key = load_config()

    # Fetch domains in pages of 1000 until empty
    domains = []
    start = 0
    while True:
        batch = list_domains(api_key, secret_api_key, start)
        if not batch:
            break
        domains.extend(batch)
        start += 1000

    # Extract just the domain names
    domain_names = [d["domain"] if isinstance(d, dict) else d for d in domains]

    # Print the list of domains
    print("Registered domains:")
    for name in domain_names:
        print(f"  - {name}")

    # For each domain, fetch and print its name servers
    print("\nName servers per domain:")
    for name in domain_names:
        try:
            ns_list = get_nameservers(api_key, secret_api_key, name)
            print(f"{name}: {', '.join(ns_list)}")
        except Exception as e:
            print(f"{name}: ERROR fetching NS — {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
