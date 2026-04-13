#!/usr/bin/env python3
"""
api_server.py - v3.0
FastAPI backend for anomaly queries and drill-down.
Supports both SQLite and Postgres backends via config.
Enhanced with WebSocket for real-time pushes, PCAP export, and timeline data.
Author: Robert Weber
"""

import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Union
import configparser
import sqlite3
import psycopg2
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import asyncio
import watchfiles
from scapy.all import Ether, IP, TCP, wrpcap

# ====================== CONFIG ======================
config = configparser.ConfigParser()
config.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])

DB_TYPE = config.get('database', 'type', fallback='sqlite').lower()
DB_PATH = Path(config.get('database', 'sqlite_path', fallback='data/baseline.db'))
ANOMALY_JSONL = Path(config.get('general', 'anomaly_jsonl', fallback='output/anomalies.jsonl'))
OUTPUT_DIR = Path(config.get('general', 'output_dir', fallback='output'))

if DB_TYPE == 'postgres':
    POSTGRES_CONN_PARAMS = {
        "dbname": config.get('postgres', 'dbname', fallback='c2_beacon_hunter'),
        "user": config.get('postgres', 'user', fallback='user'),
        "password": config.get('postgres', 'password', fallback='password'),
        "host": config.get('postgres', 'host', fallback='localhost'),
        "port": config.get('postgres', 'port', fallback=5432)
    }

app = FastAPI(title="C2 Beacon Hunter API", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=OUTPUT_DIR), name="static")


# ====================== WEBSOCKETS (EPIC 6 & EPIC 8) ======================
ui_connections: List[WebSocket] = []
agent_connections: Dict[str, WebSocket] = {}

async def watch_anomalies():
    """Pushes new anomalies to the UI Dashboard in real-time"""
    async for changes in watchfiles.awatch(ANOMALY_JSONL):
        with open(ANOMALY_JSONL, 'r') as f:
            last_line = f.readlines()[-1].strip()
            new_anomaly = json.loads(last_line)
            for ws in ui_connections:
                await ws.send_json(new_anomaly)

@app.websocket("/ws/anomalies")
async def ui_websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ui_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        ui_connections.remove(websocket)

@app.websocket("/ws/agent/{agent_id}")
async def agent_command_endpoint(websocket: WebSocket, agent_id: str):
    """Secure C2 Channel for Endpoint Agents to receive containment orders"""
    await websocket.accept()
    agent_connections[agent_id] = websocket
    print(f"[C2 API] Agent {agent_id} connected to active defense channel.")
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        print(f"[C2 API] Agent {agent_id} disconnected.")
        if agent_id in agent_connections:
            del agent_connections[agent_id]


# ====================== SOAR ENDPOINTS (EPIC 8) ======================
class ContainmentRequest(BaseModel):
    agent_id: str
    action: str = "contain"
    pid: int
    dst_ip: str
    dst_port: int

@app.post("/api/v1/soar/contain")
async def trigger_containment(req: ContainmentRequest):
    """Internal endpoint called by c2_defend.py to dispatch blocks to agents."""
    if req.agent_id in agent_connections:
        ws = agent_connections[req.agent_id]
        await ws.send_json(req.dict())
        return {"status": "success", "message": f"Containment order dispatched to {req.agent_id}"}
    else:
        raise HTTPException(status_code=404, detail=f"Agent {req.agent_id} offline")

@app.post("/api/v1/ingest/events")
async def ingest_event(event: dict):
    """Receives endpoint telemetry from lightweight agents."""
    return {"status": "accepted"}


# ====================== DATA DRILL-DOWN ENDPOINTS (EPIC 6) ======================
def get_db_connection():
    if DB_TYPE == 'postgres':
        return psycopg2.connect(**POSTGRES_CONN_PARAMS)
    else:
        return sqlite3.connect(DB_PATH)

def fetch_anomalies(limit: int = 1000, ip: Optional[str] = None, min_score: Optional[int] = None) -> List[Dict]:
    anomalies = []
    if ANOMALY_JSONL.exists():
        with open(ANOMALY_JSONL, 'r') as f:
            lines = f.readlines()
            for line in reversed(lines):
                try:
                    data = json.loads(line.strip())
                    if (not ip or ip in data.get('dst_ip', '')) and (not min_score or data.get('score', 0) >= min_score):
                        anomalies.append(data)
                    if len(anomalies) >= limit:
                        break
                except json.JSONDecodeError:
                    pass
    return anomalies

def fetch_anomaly_details(timestamp: str) -> Optional[Dict]:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        anomaly = None
        if ANOMALY_JSONL.exists():
            with open(ANOMALY_JSONL, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        if data.get('timestamp') == timestamp:
                            anomaly = data
                            break
                    except json.JSONDecodeError:
                        pass

        if not anomaly:
            raise HTTPException(status_code=404, detail="Anomaly not found")

        dst_ip = anomaly.get('dst_ip')
        pid = anomaly.get('pid')
        ts_float = datetime.fromisoformat(timestamp).timestamp()

        if DB_TYPE == 'postgres':
            cursor.execute("""
                SELECT * FROM flows
                WHERE dst_ip = %s AND pid = %s AND timestamp >= %s - 3600 AND timestamp <= %s + 3600
                ORDER BY timestamp DESC LIMIT 50
            """, (dst_ip, pid, ts_float, ts_float))
        else:
            cursor.execute("""
                SELECT * FROM flows
                WHERE dst_ip = ? AND pid = ? AND timestamp >= ? - 3600 AND timestamp <= ? + 3600
                ORDER BY timestamp DESC LIMIT 50
            """, (dst_ip, pid, ts_float, ts_float))

        flows = cursor.fetchall()
        flow_columns = [desc[0] for desc in cursor.description]
        enriched_flows = [dict(zip(flow_columns, row)) for row in flows]

        enrichment = {
            "threat_intel": f"https://example.com/threat/{dst_ip}",
            "suppression_status": "active" if any(f['suppressed'] == 0 for f in enriched_flows) else "suppressed",
            "ueba_profile": "subnet_baseline"
        }

        # Timeline Heatmap Data
        last_24h_ts = [f['timestamp'] for f in enriched_flows if ts_float - 86400 <= f['timestamp'] <= ts_float]
        last_7d_ts = [f['timestamp'] for f in enriched_flows if ts_float - 604800 <= f['timestamp'] <= ts_float]

        bins_7d = [0] * 168
        now = time.time()
        for ts in last_7d_ts:
            hour_diff = int((now - ts) / 3600)
            if 0 <= hour_diff < 168:
                bins_7d[hour_diff] += 1

        timeline = {"last_24h": last_24h_ts, "last_7d": last_7d_ts, "bins_7d": bins_7d}

        return {
            **anomaly,
            "flows_context": enriched_flows,
            "enrichment": enrichment,
            "timeline": timeline
        }
    finally:
        cursor.close()
        conn.close()

def generate_pcap(flows: List[Dict]) -> bytes:
    packets = []
    base_time = time.time()
    for i, f in enumerate(flows):
        pkt = Ether() / IP(src="192.168.1.1", dst=f['dst_ip']) / TCP(sport=12345, dport=80) / f"Entropy: {f['entropy']}"
        pkt.time = base_time + i
        packets.append(pkt)
    wrpcap("temp.pcap", packets)
    with open("temp.pcap", "rb") as f:
        pcap_data = f.read()
    os.remove("temp.pcap")
    return pcap_data

@app.get("/api/v1/anomalies")
def get_anomalies(limit: int = Query(1000), ip: Optional[str] = Query(None), min_score: Optional[int] = Query(None)):
    return fetch_anomalies(limit, ip, min_score)

@app.get("/api/v1/anomaly/{timestamp}")
def get_anomaly(timestamp: str):
    details = fetch_anomaly_details(timestamp)
    if not details:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return details

@app.get("/api/v1/anomaly/{timestamp}/pcap")
def get_anomaly_pcap(timestamp: str):
    details = fetch_anomaly_details(timestamp)
    if not details:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    pcap_data = generate_pcap(details['flows_context'])
    return Response(content=pcap_data, media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename=anomaly_{timestamp}.pcap"})

@app.get("/api/v1/ueba_profiles")
def get_ueba_profiles():
    try:
        import joblib
        return joblib.load('data/baseline_model.joblib')
    except:
        return {"profiles": {}}

@app.get("/api/v1/metrics")
def get_metrics():
    return {"total_flows_tracked": 0, "top_processes": [], "active_flows": 0}

@app.on_event("startup")
async def startup():
    asyncio.create_task(watch_anomalies())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)