#!/usr/bin/env bash
# deploy.sh — run LOCALLY to push syndicate4 to server and start everything
# Handles network interruptions: server_setup.sh runs in tmux via nohup
# Usage: ./deploy_prod.sh [--check | --logs | --attach | --status | --tunnel | --migrate]

set -euo pipefail

SERVER="${SERVER_IP:-}"
if [ -z "$SERVER" ] || [ "$SERVER" = "<your-server-ip>" ]; then
  echo "ERROR: SERVER_IP environment variable is not set or is invalid."
  echo "Please set it before deploying, for example:"
  echo "  export SERVER_IP=\"192.168.1.100\""
  echo "  ./deploy_prod.sh"
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
    ssh_cmd "tail -f /tmp/syndicate4-setup.log 2>/dev/null || echo 'No log yet'"
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
      -L 3000:localhost:3000 \
      -L 5601:localhost:5601 \
      -L 8000:localhost:8000 \
      -L 8080:localhost:8080 \
      -L 8001:localhost:8001 \
      "${USER}@${SERVER}" 2>/dev/null || \
    ssh $SSH_OPTS -N \
      -L 3000:localhost:3000 \
      -L 5601:localhost:5601 \
      -L 8000:localhost:8000 \
      -L 8080:localhost:8080 \
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
ssh_cmd "sudo mkdir -p ${REMOTE_DIR} && sudo chown -R ubuntu:ubuntu ${REMOTE_DIR}"

echo ""
echo "3. Syncing files to ${REMOTE_DIR}..."
tar -czf update.tar.gz --exclude='update.tar.gz' --exclude='.git' --exclude='keys' --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' --exclude='*.iso' --exclude='*.iso.gz' .
scp $SSH_OPTS update.tar.gz "${USER}@${SERVER}:/tmp/update.tar.gz"
ssh_cmd "sudo tar -xzf /tmp/update.tar.gz -C ${REMOTE_DIR} && sudo chown -R ubuntu:ubuntu ${REMOTE_DIR}"

echo ""
echo "4. Setting permissions..."
ssh_cmd "chmod +x ${REMOTE_DIR}/server_setup.sh ${REMOTE_DIR}/deploy.sh 2>/dev/null; true"

echo ""
echo "5. Launching setup in background..."
echo "5. Launching setup in background..."
ssh_cmd "
  # Kill old setup if still running
  sudo pkill -f 'bash.*server_setup.sh' 2>/dev/null || true

  # Run setup via nohup
  nohup sudo bash ${REMOTE_DIR}/server_setup.sh > /tmp/syndicate4-setup.log 2>&1 < /dev/null &
  echo 'Setup launched in background'
  echo 'Watch log: tail -f /tmp/syndicate4-setup.log'
"

echo ""
echo "=== DEPLOY LAUNCHED ==="
echo ""
echo "Monitor:"
echo "  ./deploy_prod.sh --logs     # tail setup log"
echo "  ./deploy_prod.sh --status   # check service status"
echo ""
echo "After services start (~5 min):"
echo "  Direct access (no tunnel needed):"
echo "  Dashboard: http://${SERVER}:3000"
echo "  Kibana:    http://${SERVER}:5601"
echo "  ML API:    http://${SERVER}:8000/docs"
echo "  Django API:http://${SERVER}:8080/api/"
