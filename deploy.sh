#!/usr/bin/env bash
# deploy.sh — run LOCALLY to push syndicate4 to server and start everything
# Handles network interruptions: server_setup.sh runs in tmux via nohup
# Usage: ./deploy.sh [--check | --logs | --attach | --status | --tunnel | --migrate]

set -euo pipefail

SERVER="${SERVER_IP:-}"
if [ -z "$SERVER" ] || [ "$SERVER" = "<your-server-ip>" ]; then
  echo "ERROR: SERVER_IP environment variable is not set or is invalid."
  echo "Please set it before deploying, for example:"
  echo "  export SERVER_IP=\"192.168.1.100\""
  echo "  ./deploy.sh"
  exit 1
fi
SSH_KEY="$(dirname "$0")/AI_lab.pem"
REMOTE_DIR="/opt/syndicate4"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o ServerAliveInterval=30"
USER="ubuntu"

# Try root if ubuntu fails (some setups use root)
ssh_cmd() {
  ssh $SSH_OPTS "${USER}@${SERVER}" "$@" 2>/dev/null || \
  ssh $SSH_OPTS "root@${SERVER}" "$@"
}

rsync_cmd() {
  rsync -avz --progress -e "ssh $SSH_OPTS" "$@" 2>/dev/null || \
  { USER="root"; rsync -avz --progress -e "ssh $SSH_OPTS" "$@"; }
}

echo "=== Syndicate4 Deploy ==="

# Sub-commands
case "${1:-deploy}" in

  --check)
    echo "Testing SSH connectivity..."
    ssh_cmd "echo '✓ Connected as $(whoami) on $(hostname)'"
    exit 0
    ;;

  --status)
    echo "Checking service status..."
    ssh_cmd "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo 'Docker not running'"
    echo ""
    ssh_cmd "curl -sf http://localhost:9200/_cluster/health?pretty 2>/dev/null || echo 'Elasticsearch: DOWN'"
    ssh_cmd "curl -sf http://localhost:8000/health 2>/dev/null || echo 'ML API: DOWN'"
    ssh_cmd "docker exec syndicate4-kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null || echo 'Kafka: DOWN'"
    exit 0
    ;;

  --migrate)
    echo "Running Django migrations on server..."
    ssh_cmd "cd /opt/syndicate4 && docker compose exec django_api python manage.py migrate"
    exit 0
    ;;

  --logs)
    echo "Streaming server logs (Ctrl+C to stop)..."
    ssh_cmd "tail -f /var/log/syndicate4-setup.log 2>/dev/null || echo 'No log yet'"
    exit 0
    ;;

  --attach)
    echo "Attaching to server tmux session..."
    ssh -t $SSH_OPTS "${USER}@${SERVER}" "tmux attach -t syndicate4 || echo 'No session found'"
    exit 0
    ;;

  --tunnel)
    echo "Starting SSH tunnel (Frontend:3000, Kibana:5601, ML API:8000, Django API:8080, Responder:8001)..."
    echo "Open browser: http://localhost:3000"
    echo "Ctrl+C to stop"
    autossh -M 0 \
      -i "$SSH_KEY" \
      -o StrictHostKeyChecking=no \
      -o ServerAliveInterval=30 \
      -o ServerAliveCountMax=3 \
      -N \
      -L 3000:localhost:80 \
      -L 5601:localhost:5601 \
      -L 8000:localhost:8000 \
      -L 8080:localhost:8088 \
      -L 8001:localhost:8001 \
      "${USER}@${SERVER}" 2>/dev/null || \
    ssh $SSH_OPTS -N \
      -L 3000:localhost:80 \
      -L 5601:localhost:5601 \
      -L 8000:localhost:8000 \
      -L 8080:localhost:8088 \
      -L 8001:localhost:8001 \
      "${USER}@${SERVER}"
    exit 0
    ;;

  deploy|"")
    ;;

  *)
    echo "Usage: $0 [--check | --status | --logs | --attach | --tunnel | --migrate | deploy]"
    exit 1
    ;;
esac

# === FULL DEPLOY ===

echo ""
echo "1. Testing connection to ${SERVER}..."
if ! ssh_cmd "echo ok" > /dev/null 2>&1; then
  echo "ERROR: Cannot connect to ${SERVER}"
  echo "Check: server reachable, key valid, user=ubuntu or root"
  exit 1
fi
echo "   Connected as ${USER}@${SERVER}"

echo ""
echo "2. Creating remote directory..."
ssh_cmd "mkdir -p ${REMOTE_DIR}"

echo ""
echo "3. Syncing files to ${REMOTE_DIR}..."
rsync_cmd \
  --exclude='.git' \
  --exclude='keys/' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.DS_Store' \
  --exclude='*.iso' \
  --exclude='*.iso.gz' \
  "$(dirname "$0")/" \
  "${USER}@${SERVER}:${REMOTE_DIR}/"

echo ""
echo "4. Setting permissions..."
ssh_cmd "chmod +x ${REMOTE_DIR}/server_setup.sh ${REMOTE_DIR}/deploy.sh 2>/dev/null; true"

echo ""
echo "5. Launching persistent setup in tmux (survives disconnects)..."
ssh_cmd "
  # Kill old setup if still running
  pkill -f 'bash.*server_setup.sh' 2>/dev/null || true

  # Start tmux if not running
  tmux new-session -d -s syndicate4 2>/dev/null || true

  # Run setup via nohup inside tmux window
  tmux send-keys -t syndicate4:0 'nohup bash ${REMOTE_DIR}/server_setup.sh > /var/log/syndicate4-setup.log 2>&1 &' Enter
  echo 'Setup launched in tmux session: syndicate4'
  echo 'Reconnect: tmux attach -t syndicate4'
  echo 'Watch log: tail -f /var/log/syndicate4-setup.log'
"

echo ""
echo "=== DEPLOY LAUNCHED ==="
echo ""
echo "Monitor:"
echo "  ./deploy.sh --logs     # tail setup log"
echo "  ./deploy.sh --attach   # attach to server tmux"
echo "  ./deploy.sh --status   # check service status"
echo ""
echo "After services start (~5 min):"
echo "  Access via SSH tunnel (recommended for hardened setup):"
echo "    ./deploy.sh --tunnel"
echo "    Dashboard: http://localhost:3000"
echo "    Kibana:    http://localhost:5601"
echo "    ML API:    http://localhost:8000/docs"
echo "    Django API:http://localhost:8080/api/"
