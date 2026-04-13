### client_parser.py ###
import json
import http.server
import socketserver
import requests
import logging
import traceback
import os
from socketserver import ThreadingMixIn

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load schema (CIM for client trimming by default; modifiable)
with open('schema.json', 'r') as f:
    SCHEMA = json.load(f)
SCHEMA_MAP = SCHEMA['cim']  # Use CIM for trimming; change to 'ecs' if needed
INFERENCES = SCHEMA_MAP.pop("inferences", {})

class ThreadedHTTPServer(ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True

class LogHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            logs = json.loads(post_data)
            if not isinstance(logs, list):
                logs = [logs]

            trimmed_logs = []
            chunk_size = int(os.getenv("CHUNK_SIZE", 1000))
            for i in range(0, len(logs), chunk_size):
                chunk = logs[i:i + chunk_size]
                for log in chunk:
                    try:
                        trimmed = trim_log(log)
                        trimmed_logs.append(trimmed)
                    except Exception as e:
                        logging.error(f"Error trimming log: {traceback.format_exc()} - Skipping log: {log}")

            if trimmed_logs:
                send_to_server(trimmed_logs)

            self.send_response(200)
            self.end_headers()
        except Exception as e:
            logging.error(f"Error processing request: {traceback.format_exc()}")
            self.send_response(500)
            self.end_headers()

def trim_log(log):
    trimmed = {}
    # Map and trim only defined fields (handles nested)
    for input_key, output_key in SCHEMA_MAP.items():
        keys = input_key.split('.')
        value = log
        for k in keys:
            value = value.get(k) if isinstance(value, dict) else None
            if value is None:
                break
        if value is not None:
            trimmed[output_key] = value

    # Apply inferences
    event_id_str = str(trimmed.get("signature_id"))
    if event_id_str in INFERENCES:
        trimmed.update(INFERENCES[event_id_str])

    return trimmed

def send_to_server(logs):
    server_url = os.getenv("SERVER_URL", "http://localhost:9880/")
    cribl_url = os.getenv("CRIBL_URL", "") # NEW: Optional Cribl endpoint
    batch_size = int(os.getenv("BATCH_SIZE", 1000))
    headers = {"Content-Type": "application/json"}

    for i in range(0, len(logs), batch_size):
        batch = logs[i:i + batch_size]

        # Send to Docker Server
        try:
            response = requests.post(server_url, json=batch, headers=headers)
            if response.status_code != 200:
                logging.error(f"Send to server failed: {response.text}")
        except Exception as e:
            logging.error(f"Error sending to server: {traceback.format_exc()}")

        # NEW: Send directly to Cribl if configured
        if cribl_url:
            try:
                cribl_response = requests.post(cribl_url, json=batch, headers=headers)
                if cribl_response.status_code != 200:
                    logging.error(f"Send to Cribl failed: {cribl_response.text}")
            except Exception as e:
                logging.error(f"Error sending to Cribl: {traceback.format_exc()}")

if __name__ == "__main__":
    PORT = 9881
    server = ThreadedHTTPServer(("", PORT), LogHandler)
    logging.info(f"Client running on port {PORT}")
    server.serve_forever()