# vigilx_ml_service/app/utils.py
import pandas as pd
import numpy as np
import re
import ipaddress

# Regex pattern to instantly extract IPv4 structures from raw string messages
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Production Mock Database representing Active Threat Intel Feeds (Malicious C2 / Botnets)
THREAT_INTEL_BLACKLIST = {
    "185.220.101.5": {"actor": "Tor_Exit_Node_Attacker", "threat_type": "SQL_Injection_Source", "confidence": 98},
    "45.227.254.12": {"actor": "Mirai_Botnet_Variant", "threat_type": "Brute_Force_Cluster", "confidence": 95},
    "193.163.125.8": {"actor": "Fancy_Bear_Proxy", "threat_type": "Exfiltration_Endpoint", "confidence": 91},
}

def extract_ip_from_record(record: dict) -> str:
    """
    Safely extracts an IP address from structured fields or parses it 
    out from the raw message text block using regex.
    """
    # Check if source_ip field was already cleanly isolated by Django regex
    if 'source_ip' in record and record['source_ip']:
        return str(record['source_ip']).strip()
    
    # Fallback: scan the message text block for any lingering IP addresses
    message = record.get('message', '')
    match = IP_REGEX.search(message)
    if match:
        return match.group(0)
        
    return "0.0.0.0"

def evaluate_threat_intelligence(ip_string: str) -> dict:
    """
    Cross-references an IP address against known threat intelligence indicators.
    Ignores private local networks (RFC 1918) automatically.
    """
    if not ip_string or ip_string == "0.0.0.0":
        return {"matched": False}

    try:
        ip_obj = ipaddress.ip_address(ip_string)
        # Skip local/private addresses to optimize system speed
        if ip_obj.is_private:
            return {"matched": False, "note": "PRIVATE_INTERNAL_LAN"}
    except ValueError:
        return {"matched": False} # Invalid IP layout

    # Database lookup
    if ip_string in THREAT_INTEL_BLACKLIST:
        intel_data = THREAT_INTEL_BLACKLIST[ip_string]
        return {
            "matched": True,
            "actor": intel_data["actor"],
            "threat_type": intel_data["threat_type"],
            "confidence_score": intel_data["confidence"]
        }

    return {"matched": False}

def transform_records_to_features(records_list: list) -> pd.DataFrame:
    """
    Transforms raw structured BSON logs into standardized numerical vectors
    optimized for Scikit-Learn inference pipelines.
    """
    df = pd.DataFrame(records_list)
    if df.empty:
        return pd.DataFrame()

    df['status_numeric'] = df['http_status'].fillna(200).astype(int)
    df['port_numeric'] = df['target_port'].fillna(80).astype(int)

    method_map = {'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4, 'OPTIONS': 5, 'UNKNOWN': 0}
    df['method_numeric'] = df['http_method'].map(lambda x: method_map.get(str(x).upper(), 0))

    severity_map = {'INFO': 1, 'WARNING': 2, 'CRITICAL': 3, 'UNKNOWN': 0}
    df['severity_numeric'] = df['severity'].map(lambda x: severity_map.get(str(x).upper(), 0))

    return df[['status_numeric', 'port_numeric', 'method_numeric', 'severity_numeric']]