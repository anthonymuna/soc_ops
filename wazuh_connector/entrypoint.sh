#!/bin/bash
# Fix Windows line endings which break SSH keys
sed -i 's/\r$//' /app/dc_siem.pem
chmod 600 /app/dc_siem.pem

echo "Starting SSH tunnels to 10.107.7.150..."
autossh -M 0 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /app/dc_siem.pem -N \
  -L 55000:127.0.0.1:55000 \
  -L 9201:127.0.0.1:9200 \
  ubuntu@10.107.7.150 &

# Give the tunnel a few seconds to establish
sleep 5

echo "Starting connector script..."
python -u connector.py
