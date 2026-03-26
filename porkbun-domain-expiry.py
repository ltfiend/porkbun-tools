#!/usr/bin/env python3
"""
Lists all Porkbun domains with expiration dates and renewal costs.
Displays a color-coded table sorted by expiration date, highlighting
domains expiring soon.
"""

import argparse
import sys
from datetime import datetime, timezone

import requests

from porkbun_common import load_config, list_domains

PRICING_URL = "https://api.porkbun.com/api/json/v3/pricing/get"


def get_pricing():
    """Fetch TLD renewal pricing from Porkbun (no auth required)."""
    resp = requests.post(PRICING_URL)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "SUCCESS":
        raise RuntimeError(f"Pricing API error: {data.get('message', data)}")
    return data.get("pricing", {})


def main():
    parser = argparse.ArgumentParser(
        description="List domains with expiration dates and renewal costs"
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to config file (default: ~/.porkbun-tools.json)"
    )
    parser.add_argument(
        "-d", "--domain",
        help="Show only this domain"
    )
    parser.add_argument(
        "-s", "--sort",
        choices=["expiry", "domain", "cost"],
        default="expiry",
        help="Sort order (default: expiry)"
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    apikey = cfg.get("api_key")
    secret = cfg.get("secret_api_key")

    # Fetch pricing
    print("Fetching TLD pricing...", end="\r", file=sys.stderr)
    pricing = get_pricing()

    # Fetch domains
    if args.domain:
        domains = [{"domain": args.domain}]
    else:
        domains = list_domains(apikey, secret)

    now = datetime.now(timezone.utc)
    rows = []

    for i, entry in enumerate(domains):
        print(f"Processing {i+1} of {len(domains)}...", end="\r", file=sys.stderr)

        domain = entry.get("domain", "")
        expire_str = entry.get("expireDate", "")
        auto_renew = entry.get("autoRenew", "")
        create_str = entry.get("createDate", "")

        # Parse expiration date
        days_left = None
        expire_display = expire_str
        if expire_str:
            try:
                expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
                days_left = (expire_dt - now).days
                expire_display = expire_dt.strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                pass

        days_str = str(days_left) if days_left is not None else "?"

        # Get TLD and renewal price
        tld = domain.split(".", 1)[1] if "." in domain else domain
        tld_pricing = pricing.get(tld, {})
        renewal_price = tld_pricing.get("renewal", "")
        if renewal_price:
            cost_str = f"${renewal_price}"
        else:
            cost_str = "?"

        ar_str = "yes" if str(auto_renew) == "1" else "no" if str(auto_renew) == "0" else str(auto_renew)

        rows.append((domain, expire_display, days_str, cost_str, ar_str, days_left))

    print(" " * 40, end="\r", file=sys.stderr)

    # Sort
    if args.sort == "domain":
        rows.sort(key=lambda r: r[0])
    elif args.sort == "cost":
        rows.sort(key=lambda r: float(r[3].lstrip("$")) if r[3] != "?" else 9999)
    else:
        rows.sort(key=lambda r: r[5] if r[5] is not None else 99999)

    # Build table (exclude days_left helper from display)
    headers = ("Domain", "Expires", "Days", "Renewal", "Auto")
    display_rows = [r[:5] for r in rows]

    col_widths = [len(h) for h in headers]
    for row in display_rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    fmt = "  ".join(f"{{:{w}}}" for w in col_widths)
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in col_widths))

    # Calculate total renewal cost
    total_cost = 0.0

    for i, (row, full) in enumerate(zip(display_rows, rows)):
        line = fmt.format(*row)
        days_left = full[5]

        # Track cost
        if row[3] != "?":
            total_cost += float(row[3].lstrip("$"))

        # Color coding based on days until expiry
        if days_left is not None and days_left < 0:
            # Expired - red background
            print("\033[101m\033[30m" + line + "\033[0m")
        elif days_left is not None and days_left <= 30:
            # Expiring within 30 days - yellow background
            print("\033[103m\033[30m" + line + "\033[0m")
        elif days_left is not None and days_left <= 90:
            # Expiring within 90 days - light magenta background
            print("\033[105m\033[30m" + line + "\033[0m")
        elif i % 2 == 1:
            print("\033[100m\033[30m" + line + "\033[0m")
        else:
            print(line)

    # Summary
    print("  ".join("-" * w for w in col_widths))
    print(f"Total domains: {len(rows)}  |  Total annual renewal: ${total_cost:.2f}")


if __name__ == "__main__":
    main()
