#!/bin/bash
set -e

# Start the Kafka broker in the background
/etc/confluent/docker/run &
KAFKA_PID=$!

echo "Waiting for Kafka to start listening on 9092..."
while ! nc -z localhost 9092; do
  sleep 1
done

echo "Kafka is up. Creating topics..."

kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --topic soc.logs.wazuh \
  --partitions 1 \
  --replication-factor 1 \
  --if-not-exists

kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --topic soc.logs.fortisiem \
  --partitions 1 \
  --replication-factor 1 \
  --if-not-exists

kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --topic soc.logs.umbrella \
  --partitions 1 \
  --replication-factor 1 \
  --if-not-exists

echo "Topics created. Waiting for Kafka to finish."

# Wait for the Kafka broker process
wait $KAFKA_PID
