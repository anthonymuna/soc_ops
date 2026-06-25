# triage.py
import os
import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from confluent_kafka import Consumer, KafkaError
from elasticsearch import Elasticsearch
from agent import get_agent_executor
from prompts import TRIAGE_SYSTEM_PROMPT

logger = logging.getLogger("triage")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "wazuh-alerts")
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
es = Elasticsearch(ES_HOST)

running = True

def start_triage_consumer():
    def consumer_thread():
        global running
        conf = {
            'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
            'group.id': 'ngao-brain-triage',
            'auto.offset.reset': 'latest',
            'enable.auto.commit': True
        }
        
        # Wait for Kafka to be fully ready
        logger.info("Initializing Kafka Consumer...")
        consumer = None
        for attempt in range(15):
            try:
                consumer = Consumer(conf)
                consumer.subscribe([KAFKA_TOPIC])
                break
            except Exception as e:
                logger.warning(f"Kafka consumer connection attempt {attempt+1}/15 failed: {e}")
                import time
                time.sleep(10)
                
        if not consumer:
            logger.error("Failed to connect to Kafka after 15 attempts. Exiting thread.")
            return
            
        logger.info(f"Kafka consumer subscribed to topic: {KAFKA_TOPIC}")
        
        # Initialize LangChain agent executor for triage
        agent_executor = get_agent_executor(TRIAGE_SYSTEM_PROMPT)
        
        while running:
            try:
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        logger.error(f"Kafka consumer error: {msg.error()}")
                        continue
                
                alert = json.loads(msg.value().decode('utf-8'))
                ml_severity = str(alert.get("ml_severity", "")).lower()
                
                if ml_severity in ["critical", "high"]:
                    logger.info(f"Starting AI triage for alert {alert.get('alert_id')} (severity: {ml_severity})")
                    
                    src_ip = alert.get("src_ip")
                    agent_name = alert.get("agent_name", "")
                    triage_id = alert.get("alert_id") or str(uuid.uuid4())
                    
                    agent_input = f"""
                    Triage request for alert:
                    - Triage ID: {triage_id}
                    - Source IP: {src_ip}
                    - Agent Name: {agent_name}
                    - Event Type: {alert.get("event_type")}
                    - Explanation: {alert.get("ml_explanation")}
                    - RF Class: {alert.get("ml_rf_class")}
                    - IF Score: {alert.get("ml_if_score")}
                    - Detected At: {alert.get("ml_detected_at")}
                    - Connector: {alert.get("connector")}
                    """
                    
                    result = agent_executor.invoke({
                        "input": agent_input,
                        "chat_history": []
                    })
                    
                    output_text = result.get("output", "").strip()
                    logger.info(f"Triage agent output for {triage_id}: {output_text}")
                    
                    # Parse JSON from agent output
                    triage_result = {}
                    try:
                        start_idx = output_text.find('{')
                        end_idx = output_text.rfind('}')
                        if start_idx != -1 and end_idx != -1:
                            json_str = output_text[start_idx:end_idx+1]
                            triage_result = json.loads(json_str)
                        else:
                            triage_result = json.loads(output_text)
                    except Exception as e:
                        logger.error(f"Failed to parse triage agent output as JSON: {e}")
                        triage_result = {
                            "incident_summary": output_text[:200],
                            "attack_pattern": "unknown",
                            "recommended_action": "monitor" if "monitor" in output_text.lower() else "block" if "block" in output_text.lower() else "dismiss",
                            "confidence": 50,
                            "mitre_techniques": alert.get("mitre_techniques", []),
                            "reasoning": "Fallback parsing due to non-JSON output"
                        }
                    
                    # Record triage result to ES index
                    triage_record = {
                        "triage_id": triage_id,
                        "alert_id": triage_id,
                        "src_ip": src_ip,
                        "agent_name": agent_name,
                        "original_severity": ml_severity,
                        "triage_summary": triage_result.get("incident_summary", ""),
                        "attack_pattern": triage_result.get("attack_pattern", ""),
                        "recommended_action": triage_result.get("recommended_action", "monitor"),
                        "confidence": triage_result.get("confidence", 50),
                        "mitre_techniques": triage_result.get("mitre_techniques", []),
                        "reasoning": triage_result.get("reasoning", ""),
                        "triaged_at": datetime.now(timezone.utc).isoformat()
                    }
                    
                    try:
                        es.index(index="syndicate4-triage", id=triage_id, body=triage_record)
                        logger.info(f"Triage record saved to Elasticsearch for {triage_id}")
                    except Exception as es_err:
                        logger.error(f"Failed to save triage record to ES: {es_err}")
                    
                    # If recommended action is block, propose it (to Postgres)
                    if triage_result.get("recommended_action") == "block":
                        from tools.propose_block import propose_block
                        propose_block.func(
                            ip=src_ip,
                            reason=triage_result.get("reasoning", "AI proposed block"),
                            severity=ml_severity,
                            triage_id=triage_id,
                            incident_summary=triage_result.get("incident_summary", ""),
                            attack_pattern=triage_result.get("attack_pattern", ""),
                            confidence=triage_result.get("confidence", 80),
                            recommended_action="block",
                            mitre_techniques_json=json.dumps(triage_result.get("mitre_techniques", [])),
                            agent_name=agent_name,
                            abuseipdb_score=0
                        )
                        
            except Exception as e:
                logger.error(f"Error processing Kafka alert message: {e}")
                
        consumer.close()
        
    t = threading.Thread(target=consumer_thread, daemon=True)
    t.start()
    return t
