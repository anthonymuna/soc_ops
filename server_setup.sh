#!/usr/bin/env bash
# server_setup.sh — runs ON the server inside tmux
# Survives SSH disconnects. Re-runnable (idempotent).

set -uo pipefail

SESSION="syndicate4"
DEPLOY_DIR="/opt/syndicate4"
LOG="/var/log/syndicate4-setup.log"

exec > >(tee -a "$LOG") 2>&1
echo "=== Syndicate4 Setup Started: $(date) ==="

# --- System deps ---
export DEBIAN_FRONTEND=noninteractive
# Ignore repo errors (e.g. stale third-party keys); ubuntu repos still work
apt-get update -qq --allow-insecure-repositories 2>&1 || apt-get update -qq 2>&1 || true
apt-get install -y -qq \
  docker.io \
  docker-compose-v2 \
  tmux \
  curl \
  wget \
  git \
  net-tools \
  htop \
  screen 2>&1 || true

systemctl enable docker
systemctl start docker

# --- vm.max_map_count for Elasticsearch ---
sysctl -w vm.max_map_count=262144
grep -q "vm.max_map_count" /etc/sysctl.conf \
  || echo "vm.max_map_count=262144" >> /etc/sysctl.conf

# --- Configure Swap Space (Prevent OOM) ---
if [ ! -f /swapfile ]; then
  echo "Creating 8GB swapfile to prevent Out-Of-Memory errors..."
  fallocate -l 8G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=8192
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
else
  echo "Swapfile already exists."
fi

# --- Create deploy dir ---
mkdir -p "$DEPLOY_DIR"

# --- Add ubuntu to docker group so non-root can use docker ---
usermod -aG docker ubuntu 2>/dev/null || true

# --- Pull & start all containers directly (no tmux send-keys) ---
echo "Pulling Docker images (this takes a few minutes)..."
cd "$DEPLOY_DIR"
docker compose pull 2>&1 | tee /var/log/syndicate4-compose-pull.log

echo "Building and starting containers..."
docker compose up --build -d 2>&1 | tee /var/log/syndicate4-compose.log
echo "docker compose up returned: $?"

# --- Setup tmux monitoring windows for reconnect ---
if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux new-session -d -s "$SESSION" -x 220 -y 50
  echo "Created tmux session: $SESSION"
fi

# Window 0: docker status
tmux send-keys -t "${SESSION}:0" "watch -n 10 'docker ps --format \"table {{.Names}}\\t{{.Status}}\\t{{.Ports}}\"'" Enter

# Window 1: live logs
tmux new-window -t "${SESSION}:1" -n "logs" 2>/dev/null || true
tmux send-keys -t "${SESSION}:1" \
  "cd $DEPLOY_DIR && docker compose logs -f --tail=50" Enter

# Window 2: health
tmux new-window -t "${SESSION}:2" -n "health" 2>/dev/null || true
tmux send-keys -t "${SESSION}:2" \
  "watch -n 15 'echo \"--- ES ---\" && curl -sf http://localhost:9200/_cluster/health?pretty; echo \"--- ML ---\" && curl -sf http://localhost:8000/health 2>/dev/null | python3 -m json.tool 2>/dev/null || echo DOWN'" Enter

# --- Wait for Elasticsearch ---
echo "Waiting for Elasticsearch..."
for i in $(seq 1 40); do
  if curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; then
    echo "Elasticsearch ready after ${i}x10s"
    break
  fi
  echo "  attempt $i/40..."
  sleep 10
done

# --- Create Elasticsearch index templates ---
curl -sf -X PUT "http://localhost:9200/_index_template/syndicate4-logs" \
  -H "Content-Type: application/json" -d '{
    "index_patterns": ["syndicate4-logs-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s"
      },
      "mappings": {
        "properties": {
          "@timestamp":         {"type": "date"},
          "event_type":         {"type": "keyword"},
          "src_ip":             {"type": "ip"},
          "dst_ip":             {"type": "ip"},
          "src_port":           {"type": "integer"},
          "dst_port":           {"type": "integer"},
          "bytes":              {"type": "long"},
          "protocol":           {"type": "keyword"},
          "threat_category":    {"type": "keyword"},
          "alert_level":        {"type": "keyword"},
          "mitre_technique":    {"type": "keyword"},
          "connection_count":   {"type": "integer"}
        }
      }
    }
  }' && echo "Log index template created"

curl -sf -X PUT "http://localhost:9200/_index_template/syndicate4-alerts" \
  -H "Content-Type: application/json" -d '{
    "index_patterns": ["syndicate4-ml-alerts", "syndicate4-alerts-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "ml_detected_at":  {"type": "date"},
          "ml_score":        {"type": "float"},
          "ml_severity":     {"type": "keyword"},
          "ml_anomaly":      {"type": "boolean"},
          "event_type":      {"type": "keyword"},
          "src_ip":          {"type": "ip"},
          "dst_ip":          {"type": "ip"}
        }
      }
    }
  }' && echo "Alert index template created"

# --- Wait for Kibana and import dashboard ---
echo "Waiting for Kibana..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:5601/api/status > /dev/null 2>&1; then
    echo "Kibana ready"
    break
  fi
  sleep 10
done

# Create Kibana data view
curl -sf -X POST "http://localhost:5601/api/data_views/data_view" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "data_view": {
      "title": "syndicate4-logs-*",
      "name": "Syndicate4 Logs",
      "timeFieldName": "@timestamp"
    }
  }' && echo "Kibana data view created"

curl -sf -X POST "http://localhost:5601/api/data_views/data_view" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "data_view": {
      "title": "syndicate4-ml-alerts",
      "name": "Syndicate4 ML Alerts",
      "timeFieldName": "ml_detected_at"
    }
  }' && echo "Kibana alerts data view created"

# --- Auto-delete docker logs every 24 hours ---
echo '#!/bin/sh' > /etc/cron.daily/docker-log-truncate
echo '/usr/bin/truncate -s 0 /var/lib/docker/containers/*/*-json.log 2>/dev/null || true' >> /etc/cron.daily/docker-log-truncate
chmod +x /etc/cron.daily/docker-log-truncate
echo "Docker log truncation cron installed"

# --- systemd service for auto-start on reboot ---
cat > /etc/systemd/system/syndicate4.service << 'EOF'
[Unit]
Description=Syndicate4 SOC Stack
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/syndicate4
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable syndicate4
echo "systemd service enabled"

echo ""
echo "=== SYNDICATE4 SETUP COMPLETE: $(date) ==="
echo ""
echo "Services:"
echo "  Elasticsearch : http://localhost:9200"
echo "  Kibana        : http://localhost:5601"
echo "  ML API        : http://localhost:8000"
echo ""
echo "Reconnect: tmux attach -t syndicate4"
echo "Logs:      tail -f /var/log/syndicate4-setup.log"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
