"""
================================================================================
DFIR RECEIVER
Bulk Ingestion, Payload Chunking, and SIEM Throttling
@RW
================================================================================
Description:
    This Flask application receives ZIP payloads from the endpoint collector,
    extracts the JSON artifacts, chunks them to prevent 429 Too Many Requests,
    and forwards them to your SIEM.

Instructions:
    1. pip install flask requests werkzeug
    2. Set AUTH_TOKEN to match the PowerShell script.
    3. Change 'ACTIVE_SIEM' to your target ("SPLUNK", "ELASTIC", "SENTINEL", etc.).
    4. Fill in the credentials for your chosen SIEM.
    5. Run: python middleware.py
================================================================================
"""

import os
import zipfile
import json
import requests
import time
import logging
import hashlib
import configparser
import base64
import hmac
import email.utils
import socket
import urllib3
import io
from flask import Flask, request, jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

# ==========================================
# CONFIGURATION
# ==========================================
config = configparser.ConfigParser()
config.read("config.ini")
def get_config(section, key, fallback=""):
    return os.getenv(f"DFIR_{key}", config.get(section, key, fallback=fallback))

AUTH_TOKEN = get_config("DEFAULT", "AUTH_TOKEN", "YOUR_BEARER_TOKEN")
ACTIVE_SIEM = get_config("DEFAULT", "ACTIVE_SIEM", "SPLUNK")
BATCH_SIZE = int(get_config("DEFAULT", "BATCH_SIZE", "500"))
THROTTLE_SLEEP = float(get_config("DEFAULT", "THROTTLE_SLEEP", "0.25"))

# SIEM Credentials
SPLUNK_HEC_URL = get_config("SPLUNK", "HEC_URL")
SPLUNK_HEC_TOKEN = get_config("SPLUNK", "HEC_TOKEN")
ELASTIC_URL = get_config("ELASTIC", "URL")
ELASTIC_API_KEY = get_config("ELASTIC", "API_KEY")
SENTINEL_WORKSPACE_ID = get_config("SENTINEL", "WORKSPACE_ID")
SENTINEL_SHARED_KEY = get_config("SENTINEL", "SHARED_KEY")
SENTINEL_LOG_TYPE = get_config("SENTINEL", "LOG_TYPE")
DD_API_KEY = get_config("DATADOG", "API_KEY")
DD_URL = get_config("DATADOG", "URL")
SYSLOG_SERVER = get_config("SYSLOG", "SERVER")
SYSLOG_PORT = int(get_config("SYSLOG", "PORT", "514"))
SYSLOG_PROTOCOL = get_config("SYSLOG", "PROTOCOL", "UDP")

# Logging (Stdout for Docker)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

# ==========================================
# SIEM FORWARDING FUNCTIONS
# ==========================================
def forward_to_splunk(hostname, timestamp, artifact_type, events):
    logging.info(f"→ Splunk {len(events)} events")
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i:i + BATCH_SIZE]
        payload = "".join(json.dumps({"host": hostname, "sourcetype": f"dfir:{artifact_type}", "time": timestamp, "event": event}) + "\n" for event in batch)
        requests.post(SPLUNK_HEC_URL, headers=headers, data=payload, verify=False)
        time.sleep(THROTTLE_SLEEP)

def forward_to_elastic(hostname, timestamp, artifact_type, events):
    logging.info(f"→ Elastic {len(events)} events")
    headers = {"Authorization": f"ApiKey {ELASTIC_API_KEY}", "Content-Type": "application/x-ndjson"}
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i:i + BATCH_SIZE]
        payload = ""
        for event in batch:
            action = {"index": {}}
            doc = {"@timestamp": timestamp, "agent": {"hostname": hostname}, "event": {"dataset": artifact_type}, "forensics": event}
            payload += json.dumps(action) + "\n" + json.dumps(doc) + "\n"
        requests.post(ELASTIC_URL, headers=headers, data=payload, verify=False)
        time.sleep(THROTTLE_SLEEP)

def forward_to_sentinel(hostname, timestamp, artifact_type, events):
    logging.info(f"→ Sentinel {len(events)} events")
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i:i + BATCH_SIZE]
        payload_array = []
        for event in batch:
            event_copy = dict(event)
            event_copy["DFIR_Host"] = hostname
            event_copy["DFIR_Artifact"] = artifact_type
            event_copy["DFIR_Timestamp"] = timestamp
            payload_array.append(event_copy)
        body = json.dumps(payload_array)
        rfc1123date = email.utils.formatdate(timeval=None, localtime=False, usegmt=True)
        string_to_hash = f"POST\n{len(body)}\napplication/json\nx-ms-date:{rfc1123date}\n/api/logs"
        decoded_key = base64.b64decode(SENTINEL_SHARED_KEY)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()).decode()
        signature = f"SharedKey {SENTINEL_WORKSPACE_ID}:{encoded_hash}"
        uri = f"https://{SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-04"
        headers = {"content-type": "application/json", "Authorization": signature, "Log-Type": SENTINEL_LOG_TYPE, "x-ms-date": rfc1123date}
        requests.post(uri, data=body, headers=headers)
        time.sleep(THROTTLE_SLEEP)

def forward_to_datadog(hostname, timestamp, artifact_type, events):
    logging.info(f"→ Datadog {len(events)} events")
    headers = {"DD-API-KEY": DD_API_KEY, "Content-Type": "application/json"}
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i:i + BATCH_SIZE]
        payload_array = [{"ddsource": "dfir_collector", "ddtags": f"host:{hostname},artifact:{artifact_type}", "hostname": hostname, "message": event} for event in batch]
        requests.post(DD_URL, headers=headers, json=payload_array)
        time.sleep(THROTTLE_SLEEP)

def forward_to_syslog(hostname, timestamp, artifact_type, events):
    logging.info(f"→ Syslog {len(events)} events")
    sock_type = socket.SOCK_STREAM if SYSLOG_PROTOCOL == "TCP" else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, sock_type)
    if SYSLOG_PROTOCOL == "TCP":
        sock.connect((SYSLOG_SERVER, SYSLOG_PORT))
    for event in events:
        payload = {"host": hostname, "timestamp": timestamp, "artifact": artifact_type, "data": event}
        message = f"<13>1 {timestamp} {hostname} DFIR_Collector - - - {json.dumps(payload)}\n"
        if SYSLOG_PROTOCOL == "TCP":
            sock.sendall(message.encode('utf-8'))
        else:
            sock.sendto(message.encode('utf-8'), (SYSLOG_SERVER, SYSLOG_PORT))
    sock.close()

def route_to_siem(hostname, timestamp, filename, data):
    artifact_type = filename.replace(".json", "")
    events = data if isinstance(data, list) else [data]
    try:
        if ACTIVE_SIEM == "SPLUNK": forward_to_splunk(hostname, timestamp, artifact_type, events)
        elif ACTIVE_SIEM == "ELASTIC": forward_to_elastic(hostname, timestamp, artifact_type, events)
        elif ACTIVE_SIEM == "SENTINEL": forward_to_sentinel(hostname, timestamp, artifact_type, events)
        elif ACTIVE_SIEM == "DATADOG": forward_to_datadog(hostname, timestamp, artifact_type, events)
        elif ACTIVE_SIEM == "SYSLOG": forward_to_syslog(hostname, timestamp, artifact_type, events)
        logging.info(f"✅ Routed {artifact_type}")
    except Exception as e:
        logging.error(f"❌ {artifact_type}: {e}")

# ==========================================
# SECURE IN-MEMORY UPLOAD ENDPOINT
# ==========================================
@app.route('/api/upload', methods=['POST'])
def handle_upload():
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        logging.warning("Unauthorized upload attempt blocked.")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or 'payload' not in data:
        return jsonify({"error": "Invalid payload"}), 400

    hostname = data.get('hostname', 'unknown_host')
    timestamp = data.get('timestamp', 'unknown_time')
    base64_payload = data['payload']

    try:
        zip_buffer = io.BytesIO(base64.b64decode(base64_payload))
        zip_sha256 = hashlib.sha256(zip_buffer.getvalue()).hexdigest()
        logging.info(f"Processing payload from {hostname} | Hash: {zip_sha256[:16]}...")

        manifest = {"hostname": hostname, "timestamp": timestamp, "zip_sha256": zip_sha256, "artifacts": {}}

        with zipfile.ZipFile(zip_buffer, 'r') as z:
            for file_info in z.infolist():
                filename = file_info.filename

                # Zip Slip Protection
                if filename.startswith('/') or '..' in filename:
                    logging.warning(f"Zip Slip attempt detected and skipped: {filename}")
                    continue

                if filename.endswith(".json"):
                    with z.open(file_info) as f:
                        file_bytes = f.read()
                        manifest["artifacts"][filename] = hashlib.sha256(file_bytes).hexdigest()

                        json_data = json.loads(file_bytes.decode('utf-8'))
                        route_to_siem(hostname, timestamp, os.path.basename(filename), json_data)

        return jsonify({"message": "Success", "zip_sha256": zip_sha256}), 200

    except zipfile.BadZipFile:
        logging.error(f"Corrupted ZIP file received from {hostname}")
        return jsonify({"error": "Invalid ZIP archive"}), 400
    except Exception as e:
        logging.error(f"Processing error for {hostname}: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logging.info(f"DFIR Receiver started - SIEM: {ACTIVE_SIEM}")
    app.run(host='0.0.0.0', port=5000)