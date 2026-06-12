#!/bin/sh
set -e

echo "Waiting for Kafka to be reachable on port 9092..."
while ! nc -z kafka 9092; do
  sleep 5
done

echo "Kafka is reachable. Starting Cisco Umbrella connector..."
exec python connector.py
