#!/bin/bash
set -e

# Target directory on the server
TARGET='/opt/syndicate4'

echo "--- 📦 Unpacking new code into $TARGET ---"
sudo mkdir -p "$TARGET"
sudo unzip -o ~/soc_ops_update.zip -d "$TARGET"

echo "--- 🚀 Building and Restarting Containers ---"
cd "$TARGET"
sudo docker compose up -d --build

echo "--- ✅ Remote Deployment Complete ---"
sudo docker ps
