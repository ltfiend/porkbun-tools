import sys
import os
import json
import subprocess
import requests
import dns.resolver
from pathlib import Path

ZONE_TEMPLATE = """
zone \"{domain}\" IN {
    type primary;
    file \"zones/db.{domain}\";
};
"""

CONFIG_FILE = "config.json"
ZONE_DIR = Path("zones")
NAMED_CONF_OUTPUT = Path("zone_config") / "{domain}.conf"
API_BASE_URL = "https://api.porkbun.com/api/json/v3"


def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)


def confirm_zone_exists(domain, dns_server):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        answers = resolver.resolve(domain, "NS")
        ns_records = [str(rdata).strip(".") for rdata in answers]
        print(f"✅ Zone {domain} confirmed with NS records: {ns_records}")
        return True
    except Exception as e:
        print(f"❌ DNS query failed: {e}")
        return False


def get_current_porkbun_nameservers(domain, config):
    endpoint = f"{API_BASE_URL}/domain/getNs/{domain}"
    payload = {"apikey": config["api_key"], "secretapikey": config["secret_api_key"]}

    try:
        response = requests.post(endpoint, json=payload)
        print(f"📥 Porkbun GET NS response status: {response.status_code}")
        print(f"📥 Porkbun GET NS raw response: {response.text}")
        response.raise_for_status()
        data = response.json()
        print(f"🔍 Current nameservers at Porkbun: {data.get('ns', [])}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Porkbun GET NS request failed: {e}")
    except json.JSONDecodeError:
        print("❌ Failed to parse Porkbun GET NS response as JSON")
        print(f"🔍 Raw response was: {response.text}")


def update_porkbun_nameservers(domain, config):
    get_current_porkbun_nameservers(domain, config)

    endpoint = f"{API_BASE_URL}/domain/updateNs/{domain}"
    payload = {
        "apikey": config["api_key"],
        "secretapikey": config["secret_api_key"],
        "ns": config["name_servers"],
    }

    try:
        response = requests.post(endpoint, json=payload)
        print(f"📡 Porkbun UPDATE NS response status: {response.status_code}")
        print(f"📡 Porkbun UPDATE NS raw response: {response.text}")
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "SUCCESS":
            print(f"✅ Porkbun updated nameservers for {domain}")
        else:
            print(f"❌ Porkbun API error: {data}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Porkbun UPDATE NS request failed: {e}")
    except json.JSONDecodeError:
        print("❌ Failed to parse Porkbun UPDATE NS response as JSON")
        print(f"🔍 Raw response was: {response.text}")


# The rest of the code remains unchanged


def create_zone_files(domain, config):
    ZONE_DIR.mkdir(parents=True, exist_ok=True)
    (Path("zone_config")).mkdir(parents=True, exist_ok=True)

    zone_file = ZONE_DIR / f"db.{domain}"
    named_conf_file = NAMED_CONF_OUTPUT.with_name(f"{domain}.conf")

    if not zone_file.exists():
        ns_records = "\n".join(
            [f"@ IN NS {ns}." for ns in config.get("name_servers", [])]
        )
        txt_record = '@ IN TXT "This is a placeholder"'
        zone_content = f"""$TTL 86400
@ IN SOA ns1.{domain}. admin.{domain}. (
    1 ; Serial
    3600 ; Refresh
    1800 ; Retry
    604800 ; Expire
    86400 ; Minimum TTL
)

{ns_records}
{txt_record}
"""
        zone_file.write_text(zone_content)
        print(f"✅ Created zone file: {zone_file}")
    else:
        print(f"ℹ️ Zone file already exists: {zone_file}")

    # med_conf_file.write_text(ZONE_TEMPLATE.format(domain=domain))
    # int(f"✅ Created named.conf fragment: {named_conf_file}")

    rndc_conf_path = config.get("rndc_conf")
    if not rndc_conf_path:
        print("❌ Missing 'rndc_conf' in config.json")
        sys.exit(1)

    zone_extras = config.get("zone_config_block")

    rndc_command = [
        "rndc",
        f"-c{rndc_conf_path}",
        "addzone",
        domain,
        f'{{ type primary; file "db.{domain}"; {zone_extras} }};',
    ]

    proceed_to_porkbun = True
    try:
        subprocess.run(rndc_command, check=True)
        print("✅ rndc addzone executed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ rndc command failed: {e}")
        response = (
            input("❓ Do you want to continue with Porkbun update anyway? [y/N]: ")
            .strip()
            .lower()
        )
        proceed_to_porkbun = response == "y"

        if config.get("catalog_zone"):
            add_catalog_zone_entry(domain, config)

    if proceed_to_porkbun:
        dns_server = config.get("dns_server")
        if dns_server and confirm_zone_exists(domain, dns_server):
            update_porkbun_nameservers(domain, config)
        else:
            print("⚠️ Skipping Porkbun update due to DNS verification failure")


def add_catalog_zone_entry(domain, config):
    import dns.tsigkeyring
    import dns.update
    import dns.query
    import hashlib

    catalog_zone = config.get("catalog_zone")
    key_path = config.get("catalog_update_key")
    catalog_server = config.get("catalog_server")

    if not catalog_zone or not key_path or not catalog_server:
        print("⚠️ Missing catalog zone configuration in config.json")
        return
    else:
        catalog_key_name = config.get("catalog_update_keyname")
        catalog_key = config.get("catalog_update_key")

    try:
        keyring = dns.tsigkeyring.from_text({catalog_key_name: catalog_key})
        zone_hash = hashlib.sha1(domain.encode()).hexdigest()
        node = f"{zone_hash}.zones.{catalog_zone}."

        update = dns.update.UpdateMessage(catalog_zone, keyring=keyring)
        update.add(node, 3600, "PTR", domain + ".")
        response = dns.query.tcp(update, catalog_server)

        if response.rcode() == 0:
            print(f"✅ Successfully added {domain} to catalog zone {catalog_zone}")
        else:
            print(
                f"❌ Failed to update catalog zone: {dns.rcode.to_text(response.rcode())}"
            )

    except Exception as e:
        print(f"❌ Error sending catalog zone nsupdate: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python porkbun_dns_update.py <domain>")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    config = load_config()
    create_zone_files(domain, config)


if __name__ == "__main__":
    main()
