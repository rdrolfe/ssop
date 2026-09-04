#!/var/ossec/framework/python/bin/python3
"""Wazuh -> DFIR-IRIS alert forwarder.

Custom Wazuh integration script: forwards level >= <configured> alerts to
the DFIR-IRIS /alerts/add API. Wired via an <integration> block in
ossec.conf (name=custom-wazuh_iris.py, hook_url, api_key, alert_format=json).

Severity mapping (Wazuh level 0-15 -> IRIS severity 1-6):
  <5 -> 2, 5-6 -> 3, 7-9 -> 4, 10-12 -> 5, >=13 -> 6
"""
import json
import logging
import sys

import requests

logging.basicConfig(
    filename="/var/ossec/logs/integrations.log", level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


def format_alert_details(alert_json):
    rule = alert_json.get("rule", {})
    agent = alert_json.get("agent", {})
    mitre = rule.get("mitre", {})
    mitre_ids = ", ".join(str(x) for x in mitre.get("id", ["N/A"]))
    mitre_tactics = ", ".join(str(x) for x in mitre.get("tactic", ["N/A"]))
    mitre_techniques = ", ".join(str(x) for x in mitre.get("technique", ["N/A"]))
    lines = [
        f"Rule ID: {rule.get('id', 'N/A')}",
        f"Rule Level: {rule.get('level', 'N/A')}",
        f"Rule Description: {rule.get('description', 'N/A')}",
        f"Agent ID: {agent.get('id', 'N/A')}",
        f"Agent Name: {agent.get('name', 'N/A')}",
        f"MITRE IDs: {mitre_ids}",
        f"MITRE Tactics: {mitre_tactics}",
        f"MITRE Techniques: {mitre_techniques}",
        f"Location: {alert_json.get('location', 'N/A')}",
        f"Full Log: {alert_json.get('full_log', 'N/A')}",
    ]
    return "\n".join(lines)


def main():
    if len(sys.argv) < 4:
        logging.error("Insufficient arguments provided. Exiting.")
        sys.exit(1)
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        with open(alert_file) as f:
            alert_json = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read alert file: {e}")
        sys.exit(1)

    details = format_alert_details(alert_json)
    level = alert_json.get("rule", {}).get("level", 0)
    if level < 5:
        severity = 2
    elif level < 7:
        severity = 3
    elif level < 10:
        severity = 4
    elif level < 13:
        severity = 5
    else:
        severity = 6

    payload = {
        "alert_title": alert_json.get("rule", {}).get("description", "No Description"),
        "alert_description": details,
        "alert_source": "Wazuh",
        "alert_source_ref": alert_json.get("id", "Unknown ID"),
        "alert_source_link": "https://192.168.1.75:5601/app/wz-home",
        "alert_severity_id": severity,
        "alert_status_id": 2,  # 'New'
        "alert_source_event_time": alert_json.get("timestamp", "Unknown Timestamp"),
        "alert_note": "",
        "alert_tags": f"wazuh,{alert_json.get('agent', {}).get('name', 'N/A')}",
        "alert_customer_id": 1,
        "alert_source_content": alert_json,
    }
    try:
        resp = requests.post(
            hook_url, data=json.dumps(payload),
            headers={"Authorization": "Bearer " + api_key,
                     "Content-Type": "application/json"},
            verify=False, timeout=20)
        if resp.status_code in (200, 201, 202, 204):
            logging.info(f"Sent alert to IRIS. Status: {resp.status_code}")
        else:
            logging.error(f"IRIS send failed. Status: {resp.status_code} "
                          f"body: {resp.text[:300]}")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to send alert to IRIS: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
