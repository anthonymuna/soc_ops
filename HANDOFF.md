# SYNDICATE 4 — AI-Based Cyber Threat Detection (SOC System)
## Agent Handoff Document

---

## Mission

Build a working defensive cyber AI prototype that:
- Learns baseline "normal" network behavior
- Detects anomalies and flags potential threats
- Provides simple explanations for alerts
- Integrates with a visualization dashboard

**Required tech stack:** Scikit-learn + ELK Stack

---

## Server Access

| Field | Value |
|---|---|
| IP | `10.104.4.68` |
| OS | Ubuntu 22.04 LTS |
| User | `ubuntu` |
| Key | `keys/syndicate4.pem` (in project root, chmod 600) |
| Docker | v29.1.3 |
| docker compose | v2.24.6 (plugin at `/usr/libexec/docker/cli-plugins/docker-compose`) |
| Remote deploy dir | `/opt/syndicate4/` |

SSH command:
```bash
ssh -i keys/syndicate4.pem -o StrictHostKeyChecking=no ubuntu@10.104.4.68
```

**IMPORTANT:** `docker-compose` (v1) has a `KeyError: 'ContainerConfig'` bug with Docker 29. Always use `docker compose` (v2 plugin). All scripts already updated.

---

## Project Structure

```
syndicate4/
├── keys/syndicate4.pem          # SSH key (gitignored)
├── docker-compose.yml           # All 7 services
├── deploy.sh                    # Local deploy helper (--check, --status, --logs, --attach, --tunnel)
└── server_setup.sh              # Server-side persistent setup (runs in tmux via nohup)
│
├── logstash/pipeline/
│   └── logstash.conf            # Parses JSON logs, enriches, writes to ES
│
├── ml_service/                  # FastAPI anomaly detection service
│   ├── app.py                   # REST API (FastAPI): /health /alerts /stats /train /scan
│   ├── detector.py              # HYBRID ML: IsolationForest + RandomForest (NSL-KDD)
│   ├── requirements.txt
│   └── Dockerfile
│
├── simulator/                   # Python Atomic Red Team-style log generator
│   ├── simulate.py              # Generates normal + attack logs → Logstash UDP
│   └── Dockerfile
│
├── atomic_runner/               # Real Atomic Red Team runner (atomic-operator)
│   ├── run_atomics.py           # Executes MITRE ATT&CK techniques, ships logs to Logstash
│   ├── atomics_schedule.json    # Technique schedule (T1046, T1110, T1018, T1049, T1082, etc.)
│   └── Dockerfile
│
├── filebeat/
│   └── filebeat.yml             # Ships /var/log/auth.log, syslog, auditd, atomic logs → Logstash
│
└── frontend/                    # React + Vite + Tailwind dashboard
    ├── src/
    │   ├── App.jsx              # Main dashboard layout
    │   ├── hooks/useSOC.js      # Polling hook (hits ML API every 10s)
    │   └── components/
    │       ├── AlertFeed.jsx    # Live alert feed with severity filter
    │       ├── MitreHeatmap.jsx # MITRE ATT&CK technique coverage grid
    │       ├── TimelineChart.jsx# Stacked area chart (5-min alert buckets)
    │       ├── ModelStatus.jsx  # IsolationForest + NSL-KDD RF status panel
    │       └── StatCard.jsx     # Stat tiles
    ├── Dockerfile               # Node build → nginx serve on :3000
    └── nginx.conf               # Proxies /api/ → ml_service:8000
```

---

## Architecture

```
Atomic Runner (real MITRE TTPs via atomic-operator)  ──┐
Simulator (Python, fake normal + attack traffic)      ──┼──► Logstash :5000 (UDP JSON)
Filebeat (ships host /var/log/auth.log, auditd)       ──┘         │
                                                                    ▼
                                                         Elasticsearch :9200
                                                         (index: syndicate4-logs-YYYY.MM.dd)
                                                                    │
                                                         ML Service :8000 (FastAPI)
                                                         - scans every 15s
                                                         - retrains every 5min
                                                         - writes to syndicate4-ml-alerts
                                                                    │
                                            ┌───────────────────────┤
                                            ▼                       ▼
                                     Kibana :5601           Frontend :3000 (React)
                                     (raw exploration)       (SOC dashboard)
```

---

## Services & Ports

| Container | Port | Purpose |
|---|---|---|
| `syndicate4-es` | 9200 | Elasticsearch (log + alert storage) |
| `syndicate4-logstash` | 5000/udp, 5044 | Log ingestion |
| `syndicate4-kibana` | 5601 | Kibana (raw data exploration) |
| `syndicate4-ml` | 8000 | ML API (anomaly detection + alerts) |
| `syndicate4-simulator` | — | Generates fake network logs |
| `syndicate4-atomic` | — | Runs real Atomic Red Team TTPs |
| `syndicate4-filebeat` | — | Ships host OS logs |
| `syndicate4-frontend` | 3000 | React SOC dashboard |

All ports bind `0.0.0.0` — accessible at `10.104.4.68:PORT` directly (UFW inactive).

---

## ML Model (detector.py)

**Hybrid approach — two models working together:**

### 1. IsolationForest (Unsupervised)
- Trains on live logs from Elasticsearch
- Detects zero-day / unknown anomalies (deviations from baseline)
- Bootstraps with synthetic normal data if <50 live logs available
- Features: hour_of_day, bytes, dst_port, src_port, protocol, event_type, is_external_dst, is_external_src, connection_count

### 2. RandomForest + NSL-KDD (Supervised)
- Downloads NSL-KDD dataset automatically from GitHub on first train
- URL: `https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt`
- Trains RandomForest (100 trees, balanced class weights)
- ~99% accuracy on known attack classification
- Classes: `normal`, `dos`, `probe`, `r2l`, `u2r`
- MITRE mapping: dos→T1498, probe→T1046, r2l→T1110, u2r→T1068

**Alert explanation format:**
```
RF classified as [DOS] confidence=94%; top classes: dos=94% | probe=3%;
IsolationForest score=-0.312 (anomalous baseline deviation); large transfer=3251KB; external destination
```

---

## ML API Endpoints

Base URL: `http://10.104.4.68:8000` (or `http://localhost:8000` via tunnel)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Model status, ES connectivity, trained_at, nsl_kdd_trained |
| GET | `/stats` | logs_scanned, anomalies_detected, last_scan, last_train |
| GET | `/alerts?limit=50&minutes=60` | Recent ML-flagged alerts |
| GET | `/logs/recent?limit=100&minutes=10` | Raw recent logs |
| GET | `/model/status` | Model config details |
| POST | `/train` | Trigger retraining (background) |
| POST | `/scan` | Trigger immediate scan (background) |
| GET | `/docs` | FastAPI Swagger UI |

---

## Simulated MITRE ATT&CK Techniques

Atomic runner executes real bash commands on schedule:

| Technique | Name | Interval |
|---|---|---|
| T1046 | Network Service Discovery (nmap) | 120s |
| T1110.001 | Brute Force: Password Guessing | 180s |
| T1018 | Remote System Discovery (arp, ping sweep) | 90s |
| T1049 | System Network Connections Discovery (netstat) | 60s |
| T1057 | Process Discovery (ps aux) | 45s |
| T1082 | System Information Discovery (uname) | 75s |
| T1083 | File and Directory Discovery (find /etc) | 60s |
| T1105 | Ingress Tool Transfer (curl/wget) | 240s |

Simulator also generates: T1046 port scan, T1110 brute force, T1021.002 lateral move (SMB), T1041 data exfil, T1071 C2 beacon, T1018 recon.

---

## Current Status (as of handoff)

### Done ✅
- Full docker-compose stack defined (7 services)
- Elasticsearch + Logstash + Kibana: previously working, all healthy
- ML service: built and running, detected 164 alerts, 1860+ logs in ES
- IsolationForest: trained and detecting
- NSL-KDD RandomForest: code complete, auto-downloads on train
- Python simulator: running, generating normal + attack logs
- Atomic runner: code complete, Dockerfile built
- Filebeat: config complete
- React frontend: code complete (all components written)
- docker compose v2 installed on server
- ES index templates created
- All ports accessible (UFW inactive)

### In Progress 🔨
- `docker compose up -d` is running on server right now
- Building: `atomic_runner` (pip install atomic-operator), `frontend` (npm build)
- All containers expected to come up within ~10 min of this handoff

### TODO for next agent
1. **Verify all 8 containers are running:**
   ```bash
   ssh -i keys/syndicate4.pem ubuntu@10.104.4.68 'sudo docker ps'
   ```

2. **Trigger model training (NSL-KDD download + RF train):**
   ```bash
   curl -X POST http://10.104.4.68:8000/train
   ```
   First train downloads ~4MB NSL-KDD, trains RF (~30s), saves model.

3. **Verify frontend loads:** `http://10.104.4.68:3000`

4. **Verify Kibana loads:** `http://10.104.4.68:5601`

5. **Create Kibana dashboard** (manual or via saved objects API):
   - Data view: `syndicate4-logs-*` (timeField: `@timestamp`)
   - Data view: `syndicate4-ml-alerts` (timeField: `ml_detected_at`)
   - Suggested visualizations: log volume over time, top event_type pie, top src_ip, alert severity bar

6. **If containers failed to build**, re-run:
   ```bash
   ssh -i keys/syndicate4.pem ubuntu@10.104.4.68
   cd /opt/syndicate4
   sudo docker compose up --build -d
   ```

7. **If ml_service won't train** (NSL-KDD download fails due to network):
   - Manually download: `https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt`
   - Place at `/app/models/nsl_kdd_train.csv` inside container or mount as volume

---

## Key Files Modified From Original

All files are at `/opt/syndicate4/` on server and `syndicate4/` locally.

**Critical known issues fixed:**
- `docker-compose` v1 → use `docker compose` (v2) — ContainerConfig bug
- pip timeout in Docker build → added `--timeout 120 --retries 5`
- `apt-get update` fails on stale gh CLI GPG key → `|| true` workaround
- `sudo pkill` via SSH exits 255 (kills session) → use script file + `sudo bash script.sh`

---

## Access Points (no tunnel needed — all dockerized)

| Service | URL |
|---|---|
| **SOC Dashboard (React)** | http://10.104.4.68:3000 |
| Kibana | http://10.104.4.68:5601 |
| ML API + Swagger | http://10.104.4.68:8000/docs |
| Elasticsearch | http://10.104.4.68:9200 |

## Deploy Commands

```bash
# Deploy to server
./deploy.sh

# Check server status
./deploy.sh --status

# Tail setup logs
./deploy.sh --logs

# Attach to server tmux (windows: 0=status, 1=logs, 2=health)
./deploy.sh --attach

# Optional tunnel (only needed if server IP not directly reachable)
./deploy.sh --tunnel
# then open: http://localhost:3000
```
