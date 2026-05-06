"""
Atomic Red Team-style log simulator.
Generates realistic network/auth logs with embedded attack bursts.
Mimics MITRE ATT&CK TTPs: T1046, T1110, T1021, T1041, T1071, T1059.
Sends JSON over UDP to Logstash.
"""

import os
import json
import random
import socket
import time
import logging
from datetime import datetime, timezone
from faker import Faker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("simulator")

fake = Faker()

LOGSTASH_HOST = os.getenv("LOGSTASH_HOST", "logstash")
LOGSTASH_PORT = int(os.getenv("LOGSTASH_PORT", "5000"))
NORMAL_RATE = float(os.getenv("NORMAL_RATE", "2.0"))
ATTACK_PROBABILITY = float(os.getenv("ATTACK_PROBABILITY", "0.08"))

INTERNAL_NETS = [
    "10.104.4", "10.104.5", "192.168.1", "172.16.0"
]

EXTERNAL_IPS = [
    "185.220.101.45", "91.108.4.100", "104.21.8.9", "45.33.32.156",
    "198.51.100.7", "203.0.113.42", "5.188.206.14", "185.107.47.215",
    "194.165.16.11", "89.248.165.29",
]

COMMON_PORTS = {
    "http": 80, "https": 443, "dns": 53, "ntp": 123,
    "smtp": 25, "ftp": 21, "ssh": 22, "rdp": 3389,
    "smb": 445, "ldap": 389, "kerberos": 88,
}


def _internal_ip() -> str:
    net = random.choice(INTERNAL_NETS)
    return f"{net}.{random.randint(1, 254)}"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _send(sock: socket.socket, log: dict):
    data = (json.dumps(log) + "\n").encode()
    try:
        sock.sendto(data, (LOGSTASH_HOST, LOGSTASH_PORT))
    except Exception as e:
        logger.warning(f"Send error: {e}")


# --- Normal traffic generators ---

def gen_http() -> dict:
    return {
        "timestamp": _ts(),
        "event_type": random.choice(["http", "https"]),
        "src_ip": _internal_ip(),
        "dst_ip": fake.ipv4_public(),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443]),
        "protocol": "tcp",
        "bytes": random.randint(200, 50000),
        "status_code": random.choices([200, 301, 404, 500], weights=[70, 15, 10, 5])[0],
        "user_agent": fake.user_agent(),
        "host": fake.domain_name(),
        "connection_count": 1,
    }


def gen_dns() -> dict:
    return {
        "timestamp": _ts(),
        "event_type": "dns",
        "src_ip": _internal_ip(),
        "dst_ip": random.choice(["8.8.8.8", "1.1.1.1", "8.8.4.4"]),
        "src_port": random.randint(1024, 65535),
        "dst_port": 53,
        "protocol": "udp",
        "bytes": random.randint(40, 512),
        "query": fake.domain_name(),
        "query_type": random.choice(["A", "AAAA", "MX", "CNAME"]),
        "connection_count": 1,
    }


def gen_auth_ok() -> dict:
    return {
        "timestamp": _ts(),
        "event_type": "ssh",
        "src_ip": _internal_ip(),
        "dst_ip": _internal_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_port": 22,
        "protocol": "tcp",
        "bytes": random.randint(1000, 8000),
        "auth_result": "success",
        "username": fake.user_name(),
        "connection_count": 1,
    }


NORMAL_GENERATORS = [gen_http, gen_http, gen_dns, gen_dns, gen_auth_ok]


# --- Attack scenario generators (Atomic Red Team TTPs) ---

def attack_port_scan() -> list[dict]:
    """T1046 - Network Service Scanning"""
    src = random.choice(EXTERNAL_IPS)
    target = _internal_ip()
    logs = []
    for port in random.sample(range(1, 65535), random.randint(50, 200)):
        logs.append({
            "timestamp": _ts(),
            "event_type": "port_scan",
            "src_ip": src,
            "dst_ip": target,
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "protocol": "tcp",
            "bytes": random.randint(40, 60),
            "tcp_flags": "SYN",
            "connection_count": 1,
            "mitre_technique": "T1046",
        })
    return logs


def attack_brute_force() -> list[dict]:
    """T1110 - Brute Force"""
    src = random.choice(EXTERNAL_IPS)
    target = _internal_ip()
    service = random.choice(["ssh", "rdp"])
    port = 22 if service == "ssh" else 3389
    logs = []
    for _ in range(random.randint(20, 100)):
        logs.append({
            "timestamp": _ts(),
            "event_type": "brute_force",
            "src_ip": src,
            "dst_ip": target,
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "protocol": "tcp",
            "bytes": random.randint(500, 2000),
            "auth_result": random.choices(["failure", "success"], weights=[95, 5])[0],
            "username": random.choice(["admin", "root", "administrator", fake.user_name()]),
            "service": service,
            "connection_count": random.randint(1, 5),
            "mitre_technique": "T1110",
        })
    return logs


def attack_lateral_movement() -> list[dict]:
    """T1021.002 - Remote Services: SMB"""
    src = _internal_ip()
    logs = []
    for _ in range(random.randint(5, 20)):
        logs.append({
            "timestamp": _ts(),
            "event_type": "lateral_movement",
            "src_ip": src,
            "dst_ip": _internal_ip(),
            "src_port": random.randint(1024, 65535),
            "dst_port": 445,
            "protocol": "tcp",
            "bytes": random.randint(5000, 100000),
            "share": random.choice(["ADMIN$", "C$", "IPC$", "SYSVOL"]),
            "username": fake.user_name(),
            "connection_count": random.randint(1, 10),
            "mitre_technique": "T1021.002",
        })
    return logs


def attack_data_exfil() -> list[dict]:
    """T1041 - Exfiltration Over C2 Channel"""
    src = _internal_ip()
    dst = random.choice(EXTERNAL_IPS)
    logs = []
    for _ in range(random.randint(3, 10)):
        logs.append({
            "timestamp": _ts(),
            "event_type": "data_exfil",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([443, 80, 8080, 4444]),
            "protocol": "tcp",
            "bytes": random.randint(500000, 5000000),
            "connection_count": random.randint(1, 3),
            "mitre_technique": "T1041",
        })
    return logs


def attack_c2_beacon() -> list[dict]:
    """T1071 - Application Layer Protocol (C2 Beacon)"""
    src = _internal_ip()
    dst = random.choice(EXTERNAL_IPS)
    logs = []
    for _ in range(random.randint(2, 8)):
        logs.append({
            "timestamp": _ts(),
            "event_type": "c2_beacon",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([443, 80, 53]),
            "protocol": random.choice(["tcp", "udp"]),
            "bytes": random.randint(200, 2000),
            "beacon_interval_seconds": random.choice([60, 120, 300, 600]),
            "connection_count": 1,
            "mitre_technique": "T1071",
        })
    return logs


def attack_recon() -> list[dict]:
    """T1018 - Remote System Discovery"""
    src = _internal_ip()
    logs = []
    for _ in range(random.randint(10, 50)):
        logs.append({
            "timestamp": _ts(),
            "event_type": "recon",
            "src_ip": src,
            "dst_ip": _internal_ip(),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([135, 137, 139, 389, 445, 3268]),
            "protocol": random.choice(["tcp", "udp"]),
            "bytes": random.randint(100, 2000),
            "connection_count": random.randint(1, 3),
            "mitre_technique": "T1018",
        })
    return logs


ATTACK_SCENARIOS = [
    attack_port_scan,
    attack_brute_force,
    attack_lateral_movement,
    attack_data_exfil,
    attack_c2_beacon,
    attack_recon,
]


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logger.info(f"Simulator started → {LOGSTASH_HOST}:{LOGSTASH_PORT}")
    logger.info(f"Normal rate: {NORMAL_RATE}/s | Attack probability: {ATTACK_PROBABILITY*100:.0f}%")

    log_count = 0
    attack_count = 0

    while True:
        # Normal traffic burst
        for _ in range(random.randint(1, 5)):
            log = random.choice(NORMAL_GENERATORS)()
            _send(sock, log)
            log_count += 1

        # Random attack scenario
        if random.random() < ATTACK_PROBABILITY:
            scenario = random.choice(ATTACK_SCENARIOS)
            attack_logs = scenario()
            for log in attack_logs:
                _send(sock, log)
            attack_count += len(attack_logs)
            logger.info(f"Attack simulated: {scenario.__name__} ({len(attack_logs)} events) | total attacks={attack_count}")

        if log_count % 500 == 0:
            logger.info(f"Stats: normal={log_count} attack={attack_count}")

        time.sleep(1.0 / NORMAL_RATE)


if __name__ == "__main__":
    main()
