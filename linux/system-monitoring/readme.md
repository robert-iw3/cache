## Linux Sentinel Security Tools

A production-hardened security monitoring tool designed to detect advanced threats using eBPF, YARA, honeypots, and anti-evasion techniques. It includes features like process monitoring, file scanning, network analysis, and a REST API for dashboard integration.

### Usage:
---

Place linux_sentinel.py and sentinel.conf in /opt/linux-sentinel/.

```bash
mkdir /opt/linux-sentinel

cp linux_sentinel.py sentinel.conf /opt/linux-sentinel
```

For systemd, copy linux-sentinel.service and linux-sentinel.timer to /etc/systemd/system/:

```bash
cp linux-sentinel.service linux-sentinel.timer /etc/systemd/system
```

Then run:

Local Docker Container

```bash
sudo chmod +x run.sh && ./run.sh
```

Kubernetes

```bash
docker|podman build -t linux-sentinel:latest .

# push to local registry
docker|podman tag linux-sentinel:latest <registry>/linux-sentinel:latest

docker|podman push <registry>/linux-sentinel:latest

# deploy
kubectl apply -f linux-sentinel-deployment.yaml

# access dashboards
kubectl -n security expose deployment linux-sentinel --type=NodePort --port=8080

kubectl -n security get svc linux-sentinel

# view logs
kubectl -n security logs -f deployment/linux-sentinel
```

### Running Modes:
---

Enhanced Mode: `python3 linux_sentinel.py enhanced` (full scan with all features).

Test Mode: `python3 linux_sentinel.py test` (verify setup).

API Mode: `python3 linux_sentinel.py api` (start REST API server).

Honeypot Mode: `python3 linux_sentinel.py honeypot` (run honeypots only).

Cleanup: `python3 linux_sentinel.py cleanup` (stop processes and clean up).

### Accessing the Dashboard:
---

Open http://127.0.0.1:8080 in a browser to view the real-time dashboard.

### Logs and Outputs:
---

Logs: /var/log/linux-sentinel/sentinel.log

Alerts: /var/log/linux-sentinel/alerts/YYYYMMDD.log

JSON Output: /var/log/linux-sentinel/latest_scan.json