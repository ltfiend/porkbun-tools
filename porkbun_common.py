"""
Shared library for Porkbun DNS management tools.
Provides common configuration loading and API interaction functions.
"""

import json
import os
import requests

# Base API URL
BASE_URL = "https://api.porkbun.com/api/json/v3"
HOME = os.path.expanduser("~")


def load_config(path=None):
    """
    Load configuration from JSON file.

    Args:
        path: Path to config file. Defaults to ~/.porkbun-tools.json

    Returns:
        dict: Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
    """
    if path is None:
        path = os.path.join(HOME, ".porkbun-tools.json")

    with open(path) as f:
        return json.load(f)


def api_call(endpoint, apikey, secretapikey, **kwargs):
    """
    Make a standardized Porkbun API call.

    Args:
        endpoint: API endpoint (e.g., "domain/listAll")
        apikey: Porkbun API key
        secretapikey: Porkbun secret API key
        **kwargs: Additional payload parameters

    Returns:
        dict: API response data

    Raises:
        RuntimeError: If API returns non-SUCCESS status
        requests.exceptions.RequestException: For network errors
    """
    url = f"{BASE_URL}/{endpoint}"
    payload = {"apikey": apikey, "secretapikey": secretapikey, **kwargs}

    resp = requests.post(url, json=payload)
    resp.raise_for_status()

    data = resp.json()
    if data.get("status") != "SUCCESS":
        raise RuntimeError(f"API error for {endpoint}: {data.get('message', data)}")

    return data


def list_domains(apikey, secretapikey, start=0):
    """
    List all domains from Porkbun.

    Args:
        apikey: Porkbun API key
        secretapikey: Porkbun secret API key
        start: Starting offset for pagination

    Returns:
        list: List of domain dictionaries
    """
    data = api_call("domain/listAll", apikey, secretapikey, start=str(start), includeLabels="no")
    return data.get("domains", [])


def get_nameservers(apikey, secretapikey, domain):
    """
    Get nameservers for a domain from Porkbun.

    Args:
        apikey: Porkbun API key
        secretapikey: Porkbun secret API key
        domain: Domain name

    Returns:
        list: List of nameserver hostnames
    """
    data = api_call(f"domain/getNs/{domain}", apikey, secretapikey)
    return data.get("ns", [])


def update_nameservers(apikey, secretapikey, domain, nameservers):
    """
    Update nameservers for a domain at Porkbun.

    Args:
        apikey: Porkbun API key
        secretapikey: Porkbun secret API key
        domain: Domain name
        nameservers: List of nameserver hostnames

    Returns:
        dict: API response data
    """
    return api_call(f"domain/updateNs/{domain}", apikey, secretapikey, ns=nameservers)


def get_ds_records(apikey, secretapikey, domain):
    """
    Get DNSSEC DS records for a domain from Porkbun.

    Args:
        apikey: Porkbun API key
        secretapikey: Porkbun secret API key
        domain: Domain name

    Returns:
        dict: Dictionary of DS records keyed by record ID
    """
    data = api_call(f"dns/getDnssecRecords/{domain}", apikey, secretapikey)
    records = data.get("records")
    return records if isinstance(records, dict) else {}


def create_ds_record(apikey, secretapikey, domain, key_tag, algorithm, digest_type, digest):
    """
    Create a DNSSEC DS record at Porkbun.

    Args:
        apikey: Porkbun API key
        secretapikey: Porkbun secret API key
        domain: Domain name
        key_tag: DNSSEC key tag (int or str)
        algorithm: DNSSEC algorithm (int or str)
        digest_type: Digest type (int or str)
        digest: Digest hex string

    Returns:
        dict: API response data
    """
    return api_call(
        f"dns/createDnssecRecord/{domain}",
        apikey,
        secretapikey,
        keyTag=str(key_tag),
        alg=str(algorithm),
        digestType=str(digest_type),
        digest=digest
    )


def delete_ds_record(apikey, secretapikey, domain, record_id):
    """
    Delete a DNSSEC DS record from Porkbun.

    Args:
        apikey: Porkbun API key
        secretapikey: Porkbun secret API key
        domain: Domain name
        record_id: DS record ID to delete

    Returns:
        dict: API response data
    """
    return api_call(f"dns/deleteDnssecRecord/{domain}/{record_id}", apikey, secretapikey)
