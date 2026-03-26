# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Collection of Python scripts for managing DNS domains via the Porkbun API, with integration for BIND9 nameservers and DNSSEC (DS record) synchronization. The tools handle nameserver updates, DNSSEC key management, zone file creation, and catalog zone integration.

The codebase uses a shared `porkbun_common.py` library that provides common configuration loading and API interaction functions to eliminate code duplication across scripts.

## Configuration

All scripts use JSON configuration files (default: `~/.porkbun-tools.json` or `porkbun-tools.json`):

```json
{
  "api_key": "<apikey>",
  "secret_api_key": "<secretkey>",
  "rndc_conf": "/etc/bind/rndc.conf",
  "dns_server": "192.168.1.1",
  "name_servers": ["ns1.example.tv", "ns2.example.tv", "ns3.example.tv"],
  "zone_template": "porkbun-ns-maint.template",
  "catalog_zone": "catalog.example",
  "catalog_server": "192.168.1.1",
  "catalog_update_keyname": "<keyname>",
  "catalog_update_key": "<updatekey>",
  "digest_type": 2
}
```

## Core Scripts

### porkbun-update-ds-sync.py
Synchronizes DS records from local BIND9 DNSKEYs to Porkbun registrar. Uses TCP queries to handle multiple DNSKEYs (more than 3).

**Usage:**
```bash
python3 porkbun-update-ds-sync.py -c ~/.porkbun-tools.json -d example.com example.org
```

**Key functions:**
- `get_dnskey()` - Queries DNSKEY records via TCP (porkbun-update-ds-sync.py:46)
- `convert_dnskey()` - Converts KSKs to DS records with specified digest type (porkbun-update-ds-sync.py:59)
- `get_existing_ds_records()` - Fetches current DS records from Porkbun API (porkbun-update-ds-sync.py:73)
- Main sync logic compares local vs remote DS records and adds/deletes as needed (porkbun-update-ds-sync.py:171-191)

### porkbun-ns-maint.py
Provisions new domains: creates zone files, adds zones to BIND9 via rndc, updates Porkbun nameservers, and adds to catalog zone.

**Usage:**
```bash
python3 porkbun-ns-maint.py -c porkbun-tools.json -d newdomain.com
```

**Workflow:**
1. Creates zone file in `zones/db.{domain}` with NS records and placeholder TXT (porkbun-ns-maint.py:105-132)
2. Loads zone template from `zone_template` config (porkbun-ns-maint.py:83-102)
3. Executes `rndc addzone` with combined configuration (porkbun-ns-maint.py:146-152)
4. Verifies zone via DNS query (porkbun-ns-maint.py:25-35)
5. Updates nameservers at Porkbun (porkbun-ns-maint.py:56-80)
6. Adds domain to catalog zone via TSIG-authenticated nsupdate (porkbun-ns-maint.py:177-211)

### porkbun-ns-list.py
Lists all domains from Porkbun and displays DNSSEC sync status with colored output.

**Usage:**
```bash
python3 porkbun-ns-list.py -c ~/.porkbun-tools.json
python3 porkbun-ns-list.py -c ~/.porkbun-tools.json -d example.com
```

**Output columns:**
- Domain name
- Nameservers (comma-separated)
- DS Key IDs (from Porkbun)
- DNSKEY Key IDs (KSK/ZSK from DNS query)
- Status (✓ in sync, ✗ out of sync)

**Color coding:**
- Red background: DS/DNSKEY mismatch (porkbun-ns-list.py:184)
- Blue background: Multiple DS records or KSKs (porkbun-ns-list.py:186-187)
- Gray background: Alternating rows (porkbun-ns-list.py:189-190)

## Architecture Notes

### Porkbun API Integration
All scripts use `https://api.porkbun.com/api/json/v3` endpoints:
- `/domain/listAll` - List domains with pagination
- `/domain/getNs/{domain}` - Get current nameservers
- `/domain/updateNs/{domain}` - Update nameservers
- `/dns/getDnssecRecords/{domain}` - Get DS records (returns dict keyed by record ID)
- `/dns/createDnssecRecord/{domain}` - Create DS record
- `/dns/deleteDnssecRecord/{domain}/{id}` - Delete DS record

API responses include `status` field ("SUCCESS" or error).

### DNSSEC Workflow
The DS sync process (porkbun-update-ds-sync.py):
1. Queries DNSKEY records via TCP to avoid UDP size limits
2. Filters for KSKs only (flags == 257)
3. Generates DS records using `dns.dnssec.make_ds()` with configurable digest type
4. Compares tuples: (keyTag, algorithm, digestType, digest)
5. Adds missing DS records, deletes stale ones
6. Logs all operations to syslog (LOG_DAEMON facility)

### BIND9 Integration
Zone provisioning via `rndc` command:
- Requires `rndc_conf` path in config
- Combines base zone config with template from `zone_template` file
- Zone files stored in `zones/` directory as `db.{domain}`
- Optional catalog zone support for automatic secondary server updates

### Catalog Zone Support
When configured (porkbun-ns-maint.py:177-211):
- Generates SHA1 hash of domain name
- Creates PTR record: `{hash}.zones.{catalog_zone}` → `{domain}`
- Uses TSIG authentication with key from config
- Sends update via `dns.update.UpdateMessage` over TCP

## Dependencies

Install dependencies with:
```bash
pip install -r requirements.txt
```

Python packages required:
- `requests>=2.31.0` - Porkbun API calls
- `dnspython>=2.4.0` - DNS queries, DNSSEC operations, TSIG authentication
- Standard library: `argparse`, `syslog`, `subprocess`, `pathlib`

## Shared Library (porkbun_common.py)

Common functions used across all scripts:
- `load_config(path=None)` - Load config from JSON (defaults to ~/.porkbun-tools.json)
- `api_call(endpoint, apikey, secretapikey, **kwargs)` - Standardized API call wrapper
- `list_domains()` - List all domains with pagination support
- `get_nameservers()` - Get nameservers for a domain
- `update_nameservers()` - Update nameservers at Porkbun
- `get_ds_records()` - Get DNSSEC DS records
- `create_ds_record()` - Create a DS record
- `delete_ds_record()` - Delete a DS record

All API functions raise `RuntimeError` on non-SUCCESS status for consistent error handling.

## Output Conventions

Scripts use emoji indicators consistently:
- ✅ Success operations
- ❌ Errors and failures
- ℹ️ Informational messages
- ⚠️ Warnings
- 📡 / 📥 API requests/responses
- 🔍 Debug information
- [+] Adding records
- [-] Deleting records
- [=] Already in sync
