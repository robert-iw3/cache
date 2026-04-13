# Workflow

### 1. Prepare Files (One-time)
Place all files in one folder:
- schema.json
- client_parser.py
- server_parser.py
- Dockerfile.client
- Dockerfile.server
- docker-compose.client.yml
- docker-compose.server.yml

### 2. Configure (One-time)
- Edit `schema.json` (add mappings/inferences if needed)
- In `docker-compose.client.yml`: set `SERVER_URL` = http://<server-ip>:9880/
- In `docker-compose.server.yml`:
  - `OUTPUT_TYPE` = Splunk or Elastic
  - Splunk: fill `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN`
  - Elastic: set `ELASTIC_URL` (direct, Logstash, or Agent endpoint)

### 3. Start Containers
**Recommended (orchestration script):**
```powershell
.\Orchestrate-Deployment.ps1 -Deployment Client/Server
```

- Manual
```bash
docker-compose -f docker-compose.server.yml up --build -d
docker-compose -f docker-compose.client.yml up --build -d
```

### 4. Send Events to Client
Run this PowerShell (or schedule it):

```pwsh
$events = Get-WinEvent -LogName Security -MaxEvents 50 | ConvertTo-Json -Depth 5 -Compress
Invoke-WebRequest -Uri http://localhost:9881/ -Method Post -Body $events -ContentType application/json
```

### 5. Verify

- Check containers: docker ps
- Check logs: docker logs <container-name>
- Check SIEM:
    - Splunk: index=main sourcetype=_json tag=authentication
    - Elastic: index:logs-ecs* event.code:4624

Events → Client (parse/trim) → Server → SIEM.
