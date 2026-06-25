# SYNDICATE 4 — AI-Based Cyber Threat Detection

Defensive SOC system that detects network intrusions using machine learning, simulates real attacks using Atomic Red Team, and visualizes everything on a live dashboard.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     ATTACK SIMULATION                        │
│                                                             │
│                      Python Simulator                       │
│                   (network traffic gen)                     │
│                     HTTP, DNS, SSH, SMB                     │
│                   port scans, C2 beacons                    │
│                     data exfiltration                       │
│                     lateral movement                        │
└─────────────────────────────────────────────────────────────┘
                     │ JSON over UDP
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      LOG PIPELINE                            │
│                                                              │
│  Logstash (port 5000/5044)                                   │
│  - Parses + enriches JSON logs                               │
│  - Tags internal vs external IPs                             │
│  - Classifies suspicious vs normal                           │
│  - Routes to Elasticsearch                                   │
│                                                              │
│  Filebeat (sidecar)                                          │
│  - Ships /var/log/auth.log, syslog, auditd from host OS      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    ELASTICSEARCH                             │
│                                                              │
│  syndicate4-logs-YYYY.MM.dd   ← all network events          │
│  syndicate4-ml-alerts         ← ML-flagged anomalies         │
│  syndicate4-alerts-*          ← Logstash-flagged suspicious  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   AI DETECTION ENGINE                        │
│                                                              │
│  Runs every 15 seconds. Retrains every 5 minutes.           │
│                                                              │
│  Model 1: IsolationForest (Unsupervised)                    │
│  - Learns what "normal" looks like from live logs           │
│  - Flags statistical outliers as anomalies                  │
│  - Catches zero-day / unknown attack patterns               │
│                                                              │
│  Model 2: RandomForest + NSL-KDD (Supervised)               │
│  - Trained on 125,000+ labeled network intrusion records    │
│  - Classifies exact attack type:                            │
│      DoS  → volumetric flooding attacks                     │
│      Probe → reconnaissance / scanning                      │
│      R2L  → remote-to-local exploitation                    │
│      U2R  → privilege escalation                            │
│  - ~99% accuracy on known attack families                   │
│                                                              │
│  Alert explanation (example):                               │
│  "RF classified as [DOS] confidence=94%;                    │
│   IsolationForest score=-0.312; large transfer=3251KB;      │
│   external destination"                                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    SOC DASHBOARD (React)                     │
│                  http://<server-ip>:3000                     │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Logs     │ │ ML       │ │ Critical │ │ Session  │       │
│  │ Scanned  │ │ Alerts   │ │ Count    │ │ Alerts   │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│                                                              │
│  [Alert Timeline — stacked area chart by severity]          │
│                                                              │
│  [Live Alert Feed]          [AI Model Status]               │
│  severity badge             IsolationForest: ACTIVE          │
│  event type                 NSL-KDD RF: ACTIVE (~99%)        │
│  src_ip → dst_ip            trained_at / samples             │
│  explanation text                                            │
│  MITRE technique                                             │
│                                                              │
│  [MITRE ATT&CK Heatmap — technique hit counts]              │
│  T1046 T1018 T1049 T1110 T1021 T1041 T1071 ...              │
│                                                              │
│  [RF Attack Classification breakdown bar chart]             │
│  dos / probe / r2l / u2r / normal                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Services

| Container | Port | Role |
|---|---|---|
| `syndicate4-es` | 9200 | Elasticsearch — stores all logs and alerts |
| `syndicate4-logstash` | 5000/udp, 5044 | Ingests and enriches logs |
| `syndicate4-kibana` | 5601 | Raw data exploration (analysts) |
| `syndicate4-ml` | 8000 | AI detection engine + REST API |
| `syndicate4-simulator` | — | Continuous network traffic generator |
| `syndicate4-filebeat` | — | Ships host OS logs |
| `syndicate4-frontend` | 3000 | React SOC dashboard (end users) |

---

## What Gets Detected

### From Network Simulator (synthetic traffic)
- Normal: HTTP, HTTPS, DNS, NTP, SSH, SMTP
- Attacks: port scan, brute force, lateral movement (SMB), data exfiltration, C2 beaconing, recon

---

## ML API

Base URL: `http://<server-ip>:8000`

| Endpoint | Description |
|---|---|
| `GET /health` | Model status, training info |
| `GET /alerts?limit=50&minutes=60` | Recent ML-detected anomalies |
| `GET /stats` | Logs scanned, anomalies detected, scan errors |
| `GET /logs/recent` | Raw recent logs from ES |
| `POST /train` | Trigger model retraining |
| `GET /docs` | Interactive Swagger UI |

---

## Alert Severity Levels

| Level | Condition |
|---|---|
| **Critical** | RF classifies as U2R or R2L with >70% confidence, OR IsolationForest score < -0.30 |
| **High** | RF classifies as DoS with >70% confidence, OR IF score < -0.15 |
| **Medium** | RF classifies as Probe with >60% confidence, OR IF score < -0.05 |
| **Low** | Weak anomaly signal |

---

## Quick Start

```bash
# Clone and enter project
cd syndicate4/

# Deploy to server (first time)
./deploy.sh

# Check everything is running
./deploy.sh --status

# Open dashboard
open http://<server-ip>:3000

# Trigger manual model retrain
curl -X POST http://<server-ip>:8000/train

# Watch live alerts
curl http://<server-ip>:8000/alerts?limit=10 | python3 -m json.tool

# SSH to server
ssh -i keys/syndicate4.pem ubuntu@<server-ip>

# On server — restart all containers
cd /opt/syndicate4 && sudo docker compose up -d
```

---

## Auto-Restart on Reboot

systemd service `syndicate4.service` is enabled on the server. On every reboot, all containers start automatically via `docker compose up -d`.

```bash
# Check service status
sudo systemctl status syndicate4

# Manual restart
sudo systemctl restart syndicate4
```
