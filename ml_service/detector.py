"""
Hybrid detection pipeline:
  1. RandomForest on NSL-KDD (supervised — attack family classification)
  2. Supervised classifier on labeled live logs (uses threat_category label from ES)
  3. Zero-shot NLI classifier via HuggingFace (no training, no fine-tuning)
  4. IsolationForest fallback (unsupervised baseline)
"""

import os
import logging
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import threading

import zlib
import json
import httpx
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, RandomizedSearchCV

MODEL_PATH        = Path("/app/models/detector.pkl")
NSL_KDD_PATH      = Path("/app/models/nsl_kdd_train.csv")
NSL_KDD_TEST_PATH = Path("/app/models/nsl_kdd_test.csv")
CONTAMINATION     = float(os.getenv("CONTAMINATION", "0.05"))
HF_MODEL          = os.getenv("HF_ZS_MODEL", "cross-encoder/nli-MiniLM2-L6-H768")
USE_ZS_CLASSIFIER = os.getenv("USE_ZS_CLASSIFIER", "true").lower() == "true"

NSL_KDD_URL      = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
NSL_KDD_TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

logger = logging.getLogger("detector")

QWEN_API_URL = os.getenv("QWEN_API_URL", "https://localhost/v1").rstrip('/')
QWEN_API_KEY = os.getenv("QWEN_API_KEY", "")

NSL_KDD_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

ATTACK_FAMILIES = {
    "normal": "normal",
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "mailbomb": "dos",
    "apache2": "dos", "processtable": "dos", "udpstorm": "dos",
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe",
    "mscan": "probe", "saint": "probe",
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "sendmail": "r2l", "named": "r2l", "snmpgetattack": "r2l", "snmpguess": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "httptunnel": "r2l",
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r",
    "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r",
}

# Mapping from threat_category field in ES logs → attack family
THREAT_CAT_MAP = {
    "normal": "normal",
    "dos": "dos", "ddos": "dos",
    "probe": "probe", "recon": "probe", "port_scan": "probe",
    "brute_force": "r2l", "r2l": "r2l", "lateral_movement": "r2l",
    "c2": "u2r", "c2_beacon": "u2r", "privesc": "u2r",
    "data_exfil": "u2r", "exfil": "u2r",
    "u2r": "u2r",
}

# Attack labels for zero-shot classifier
ZS_LABELS = [
    "normal network traffic",
    "denial of service attack",
    "network port scanning",
    "brute force authentication attack",
    "command and control beaconing",
    "data exfiltration",
    "lateral movement",
    "privilege escalation",
]

ZS_LABEL_TO_CLASS = {
    "normal network traffic": "normal",
    "denial of service attack": "dos",
    "network port scanning": "probe",
    "brute force authentication attack": "r2l",
    "command and control beaconing": "u2r",
    "data exfiltration": "u2r",
    "lateral movement": "r2l",
    "privilege escalation": "u2r",
}

FEATURE_NAMES = [
    "hour_of_day", "bytes", "dst_port", "src_port",
    "protocol_encoded", "event_type_encoded",
    "is_external_dst", "is_external_src", "connection_count_proxy",
    "mitre_tactic_hash", "mitre_technique_hash",
]

EVENT_TYPE_MAP = {
    "dns": 0, "http": 1, "https": 2, "ntp": 3, "smtp": 4,
    "ftp": 5, "ssh": 6, "rdp": 7, "smb": 8,
    "port_scan": 10, "brute_force": 11, "lateral_movement": 12,
    "data_exfil": 13, "c2_beacon": 14, "recon": 15, "privesc": 16,
    "syscheck": 17, "rootcheck": 18, "sca": 19, "localfile": 20,
}

PROTOCOL_MAP = {"tcp": 0, "udp": 1, "icmp": 2, "other": 3}

PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "::1",
)

CLASS_LABELS = ["normal", "dos", "probe", "r2l", "u2r", "unknown_anomaly"]
SEV_MAP = {
    "normal": "info", "dos": "critical", "probe": "medium",
    "r2l": "high", "u2r": "critical", "unknown_anomaly": "high",
}

# Simplified IP-to-Country mapping for demonstration
GEO_MAP = {
    "10.": "Local Network",
    "192.168.": "Private Network",
    "172.16.": "Private Network",
    "172.17.": "Private Network",
    "172.18.": "Private Network",
    "172.19.": "Private Network",
    "127.": "Loopback",
    "8.8.8.8": "USA (Google)",
    "1.1.1.1": "USA (Cloudflare)",
    "45.33.": "USA (Linode)",
    "185.199.": "USA (GitHub)",
    "10.104.": "Internal SOC Lab",
}


def _get_geo(ip: str) -> str:
    for prefix, country in GEO_MAP.items():
        if str(ip).startswith(prefix):
            return country
    return "External / Unknown"


def _is_external(ip: str) -> int:
    if not ip or ip in ("null", "None"):
        return 0
    s = str(ip)
    return 0 if any(s.startswith(p) for p in PRIVATE_PREFIXES) else 1


def _hash_mitre(val: str) -> int:
    if not val: return 0
    return zlib.crc32(val.encode('utf-8')) % 1000


def _download_file(url: str, dest: Path) -> bool:
    if dest.exists():
        return True
    logger.info(f"Downloading {url}...")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        dest.write_bytes(data)
        logger.info(f"Downloaded {dest.name}: {len(data)//1024}KB")
        return True
    except Exception as e:
        logger.error(f"Download failed {url}: {e}")
        return False


def _parse_nsl_kdd_raw(path: Path):
    try:
        X_rows, y_rows = [], []
        cat_cols: dict[str, dict] = {"protocol_type": {}, "service": {}, "flag": {}}
        with open(path) as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 43:
                    continue
                row = dict(zip(NSL_KDD_COLS, parts))
                for col, enc in cat_cols.items():
                    v = row[col]
                    if v not in enc:
                        enc[v] = len(enc)
                    row[col] = enc[v]
                features = [float(row[c]) if c not in cat_cols else row[c]
                            for c in list(cat_cols.keys())]
                features = [
                    float(row["duration"]), float(row["protocol_type"]),
                    float(row["service"]), float(row["flag"]),
                    min(float(row["src_bytes"]), 1e7), min(float(row["dst_bytes"]), 1e7),
                    float(row["land"]), float(row["wrong_fragment"]), float(row["urgent"]),
                    float(row["hot"]), float(row["num_failed_logins"]), float(row["logged_in"]),
                    float(row["num_compromised"]), float(row["root_shell"]),
                    float(row["su_attempted"]), float(row["num_root"]),
                    float(row["num_file_creations"]), float(row["num_shells"]),
                    float(row["num_access_files"]), float(row["num_outbound_cmds"]),
                    float(row["is_host_login"]), float(row["is_guest_login"]),
                    float(row["count"]), float(row["srv_count"]),
                    float(row["serror_rate"]), float(row["srv_serror_rate"]),
                    float(row["rerror_rate"]), float(row["srv_rerror_rate"]),
                    float(row["same_srv_rate"]), float(row["diff_srv_rate"]),
                    float(row["srv_diff_host_rate"]), float(row["dst_host_count"]),
                    float(row["dst_host_srv_count"]), float(row["dst_host_same_srv_rate"]),
                    float(row["dst_host_diff_srv_rate"]), float(row["dst_host_same_src_port_rate"]),
                    float(row["dst_host_srv_diff_host_rate"]), float(row["dst_host_serror_rate"]),
                    float(row["dst_host_srv_serror_rate"]), float(row["dst_host_rerror_rate"]),
                    float(row["dst_host_srv_rerror_rate"]),
                ]
                label_raw = row["label"].strip().rstrip(".")
                label = ATTACK_FAMILIES.get(label_raw.lower(), "u2r")
                X_rows.append(features)
                y_rows.append(label)
        return np.array(X_rows, dtype=np.float32), y_rows
    except Exception as e:
        logger.error(f"NSL-KDD parse error {path}: {e}")
        return None


def _load_nsl_kdd():
    if not _download_file(NSL_KDD_URL, NSL_KDD_PATH):
        return None
    result = _parse_nsl_kdd_raw(NSL_KDD_PATH)
    if result is None:
        return None
    X, y_strings = result
    le = LabelEncoder()
    y = le.fit_transform(y_strings)
    return X, y, list(le.classes_)


def extract_features(logs: list[dict]) -> np.ndarray:
    rows = []
    for log in logs:
        ts = log.get("@timestamp", log.get("timestamp", ""))
        try:
            hour = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).hour
        except Exception:
            hour = 0
            
        rule = log.get("rule", {})
        mitre = rule.get("mitre", {})
        tactic = mitre.get("tactic", [""])[0] if mitre.get("tactic") else ""
        technique = mitre.get("technique", [""])[0] if mitre.get("technique") else ""
        
        row = [
            hour,
            min(int(log.get("bytes", 0)), 10_000_000),
            int(log.get("dst_port", 0)),
            int(log.get("src_port", 0)),
            PROTOCOL_MAP.get(str(log.get("protocol", "other")).lower(), 3),
            EVENT_TYPE_MAP.get(str(log.get("event_type", "")).lower(), -1),
            _is_external(str(log.get("dst_ip", "10.0.0.1"))),
            _is_external(str(log.get("src_ip", "10.0.0.1"))),
            int(log.get("connection_count", 1)),
            _hash_mitre(tactic),
            _hash_mitre(technique),
        ]
        rows.append(row)
    return np.array(rows, dtype=np.float32)


def log_to_text(log: dict) -> str:
    """Convert log dict to natural language for zero-shot NLI classifier."""
    parts = []
    et = log.get("event_type", "")
    if et:
        parts.append(str(et).replace("_", " "))
    proto = log.get("protocol", "")
    if proto:
        parts.append(f"{proto} traffic")
    src = log.get("src_ip", "")
    dst = log.get("dst_ip", "")
    if src and dst:
        src_ext = _is_external(src)
        dst_ext = _is_external(dst)
        parts.append(f"from {'external' if src_ext else 'internal'} host {src}")
        parts.append(f"to {'external' if dst_ext else 'internal'} host {dst}")
    port = log.get("dst_port", 0)
    if port:
        parts.append(f"port {port}")
    b = int(log.get("bytes", 0))
    if b > 0:
        parts.append(f"{b} bytes")
    cc = int(log.get("connection_count", 0))
    if cc > 1:
        parts.append(f"{cc} connections")
        
    rule = log.get("rule", {})
    mitre = rule.get("mitre", {})
    tactics = mitre.get("tactic", [])
    techniques = mitre.get("technique", [])
    if tactics:
        parts.append(f"MITRE Tactic: {', '.join(tactics)}")
    if techniques:
        parts.append(f"MITRE Technique: {', '.join(techniques)}")
        
    cat = log.get("threat_category", "")
    if cat and cat != "normal":
        parts.append(f"classified as {str(cat).replace('_', ' ')}")
    return ". ".join(parts) if parts else "network traffic event"


def _extract_labeled_logs(logs: list[dict]) -> tuple[np.ndarray, list[str]] | None:
    """
    Use threat_category label already in ES logs for supervised training.
    This is the key fix: all logs are labeled — stop filtering to 'normal only'.
    """
    X_rows, y_rows = [], []
    for log in logs:
        cat = log.get("threat_category", "")
        if isinstance(cat, list):
            cat = cat[0]
        cat = str(cat).lower()
        family = THREAT_CAT_MAP.get(cat)
        if family is None:
            # Infer from event_type
            et = str(log.get("event_type", "")).lower()
            family = THREAT_CAT_MAP.get(et, "normal")
        ts = log.get("@timestamp", "")
        try:
            hour = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).hour
        except Exception:
            hour = 0
            
        rule = log.get("rule", {})
        mitre = rule.get("mitre", {})
        tactic = mitre.get("tactic", [""])[0] if mitre.get("tactic") else ""
        technique = mitre.get("technique", [""])[0] if mitre.get("technique") else ""
        
        row = [
            hour,
            min(int(log.get("bytes", 0)), 10_000_000),
            int(log.get("dst_port", 0)),
            int(log.get("src_port", 0)),
            PROTOCOL_MAP.get(str(log.get("protocol", "other")).lower(), 3),
            EVENT_TYPE_MAP.get(str(log.get("event_type", "")).lower(), -1),
            _is_external(str(log.get("dst_ip", "10.0.0.1"))),
            _is_external(str(log.get("src_ip", "10.0.0.1"))),
            int(log.get("connection_count", 1)),
            _hash_mitre(tactic),
            _hash_mitre(technique),
        ]
        X_rows.append(row)
        y_rows.append(family)

    if not X_rows:
        return None
    return np.array(X_rows, dtype=np.float32), y_rows


class QwenClassifier:
    """
    Qwen zero-shot NLI classifier replacement.
    Calls self-hosted Qwen LLM endpoint.
    """

    def __init__(self):
        self._available = False
        self._load()

    def _load(self):
        def _target():
            try:
                logger.info("Pinging Qwen model endpoint...")
                with httpx.Client(verify=False, timeout=5) as client:
                    res = client.get(f"{QWEN_API_URL}/models")
                if res.status_code == 200:
                    self._available = True
                    logger.info("Qwen classifier ready")
                else:
                    logger.warning(f"Qwen classifier unavailable: status {res.status_code}")
                    self._available = False
            except Exception as e:
                logger.warning(f"Qwen classifier unavailable: {e}")
                self._available = False
        
        t = threading.Thread(target=_target, daemon=True)
        t.start()

    def classify(self, texts: list[str]) -> list[dict]:
        """Returns list of {label, score, rf_class} for each text."""
        if not self._available or not texts:
            return [{"label": "unknown", "score": 0.0, "rf_class": "unknown_anomaly"}] * len(texts)
        
        results = []
        url = f"{QWEN_API_URL}/chat/completions"
        headers = {
            "Authorization": f"Bearer {QWEN_API_KEY}"
        }
        
        system_prompt = (
            "You are a network traffic classifier. Classify the provided log text into EXACTLY ONE of these categories: "
            "normal, dos, probe, r2l, u2r, unknown_anomaly. "
            "Return ONLY valid JSON in the exact format: "
            "{\"rf_class\": \"<category>\", \"score\": <confidence 0.0-1.0>, \"label\": \"<brief description>\"}"
        )
        
        with httpx.Client(verify=False, timeout=15) as client:
            for text in texts:
                try:
                    payload = {
                        "model": "Qwen/Qwen2.5-3B-Instruct",
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": text}
                        ],
                        "max_tokens": 200
                    }
                    res = client.post(url, headers=headers, json=payload)
                    res.raise_for_status()
                    
                    content = res.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                    
                    # Strip markdown fences
                    if content.startswith("```json"):
                        content = content[7:]
                    elif content.startswith("```"):
                        content = content[3:]
                    if content.endswith("```"):
                        content = content[:-3]
                        
                    data = json.loads(content.strip())
                    rf_class = data.get("rf_class", "unknown_anomaly")
                    if rf_class not in ["normal", "dos", "probe", "r2l", "u2r", "unknown_anomaly"]:
                        rf_class = "unknown_anomaly"
                        
                    results.append({
                        "label": data.get("label", "unknown"),
                        "score": float(data.get("score", 0.0)),
                        "rf_class": rf_class
                    })
                except Exception as e:
                    logger.debug(f"Qwen classify error: {e}")
                    results.append({"label": "unknown", "score": 0.0, "rf_class": "unknown_anomaly"})
                    
        return results

    @property
    def available(self):
        return self._available


class QwenNarrator:
    """Replaces _explain() string concatenation with analyst-grade summaries."""

    def __init__(self):
        self._available = False
        self._load()
        
    def _load(self):
        def _target():
            try:
                with httpx.Client(verify=False, timeout=5) as client:
                    res = client.get(f"{QWEN_API_URL}/models")
                if res.status_code == 200:
                    self._available = True
                else:
                    self._available = False
            except Exception:
                self._available = False
        t = threading.Thread(target=_target, daemon=True)
        t.start()

    def narrate(self, alert: dict) -> str:
        """Generates 2-3 sentence analyst summary."""
        if not self._available:
            return ""
            
        url = f"{QWEN_API_URL}/chat/completions"
        headers = {
            "Authorization": f"Bearer {QWEN_API_KEY}"
        }
        
        system_prompt = (
            "You are a SOC analyst. Write a concise 2-3 sentence threat summary based on the provided alert JSON. "
            "Cover: 1. What happened (attack type, src_ip -> dst_ip, port). "
            "2. Why it is suspicious (detection layers, confidence). "
            "3. Recommended immediate action. "
            "No markdown, no bullet points, plain text only."
        )
        
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                payload = {
                    "model": "Qwen/Qwen2.5-3B-Instruct",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": json.dumps(alert)}
                    ],
                    "max_tokens": 300
                }
                res = client.post(url, headers=headers, json=payload)
                res.raise_for_status()
                return res.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        except Exception as e:
            logger.debug(f"Qwen narrate error: {e}")
            return ""
            
    @property
    def available(self):
        return self._available


class AnomalyDetector:
    def __init__(self):
        self.rf_pipeline: Pipeline | None = None      # NSL-KDD trained
        self.live_pipeline: Pipeline | None = None    # Live labeled logs trained
        self.if_pipeline: Pipeline | None = None      # IsolationForest fallback
        self.rf_classes: list[str] = []
        self.live_classes: list[str] = []
        self.trained_at: datetime | None = None
        self.training_samples: int = 0
        self.nsl_kdd_trained: bool = False
        self.live_supervised: bool = False
        self.live_supervised: bool = False
        self.zs_classifier = QwenClassifier() if USE_ZS_CLASSIFIER else None
        self.narrator = QwenNarrator()
        self._load()

    def _load(self):
        if MODEL_PATH.exists():
            try:
                data = joblib.load(MODEL_PATH)
                self.rf_pipeline    = data.get("rf_pipeline")
                self.live_pipeline  = data.get("live_pipeline")
                self.if_pipeline    = data.get("if_pipeline")
                self.rf_classes     = data.get("rf_classes", [])
                self.live_classes   = data.get("live_classes", [])
                self.trained_at     = data.get("trained_at")
                self.training_samples = data.get("training_samples", 0)
                self.nsl_kdd_trained  = data.get("nsl_kdd_trained", False)
                self.live_supervised  = data.get("live_supervised", False)
                logger.info(f"Model loaded: nsl_kdd={self.nsl_kdd_trained} "
                            f"live_supervised={self.live_supervised} "
                            f"samples={self.training_samples}")
            except Exception as e:
                logger.warning(f"Model load error: {e}")

    def is_trained(self) -> bool:
        return self.if_pipeline is not None or self.rf_pipeline is not None

    def train(self, live_logs: list[dict]) -> dict:
        result = {}

        # 1. NSL-KDD → RandomForest (supervised, offline dataset)
        nsl = _load_nsl_kdd()
        if nsl is not None:
            X_kdd, y_kdd, classes = nsl
            logger.info(f"Training RF on {len(X_kdd)} NSL-KDD samples ({len(classes)} classes)...")
            base_pipe = Pipeline([
                ("scaler", StandardScaler()),
                ("rf", RandomForestClassifier(random_state=42, n_jobs=1)),
            ])
            param_dist = {
                "rf__n_estimators": [100, 200, 300],
                "rf__max_depth": [10, 15, None],
                "rf__min_samples_split": [2, 5, 10]
            }
            search = RandomizedSearchCV(base_pipe, param_dist, n_iter=5, cv=3, n_jobs=2, random_state=42)
            X_tr, X_te, y_tr, y_te = train_test_split(X_kdd, y_kdd, test_size=0.1, random_state=42)
            search.fit(X_tr, y_tr)
            
            acc = search.score(X_te, y_te)
            self.rf_pipeline = search.best_estimator_
            self.rf_classes = classes
            self.nsl_kdd_trained = True
            
            result["rf_accuracy"] = round(acc, 4)
            result["rf_best_params"] = search.best_params_
            result["rf_classes"] = classes
            logger.info(f"NSL-KDD RF best params: {search.best_params_}, accuracy: {acc:.4f}")

        # 2. Live labeled logs → supervised classifier
        # KEY FIX: use ALL logs with their threat_category labels — not "normal only"
        if live_logs:
            labeled = _extract_labeled_logs(live_logs)
            if labeled is not None:
                X_live, y_live = labeled
                unique_classes = list(set(y_live))
                logger.info(f"Training live classifier on {len(X_live)} labeled logs "
                            f"({len(unique_classes)} classes: {unique_classes})")
                if len(unique_classes) >= 2:
                    le = LabelEncoder()
                    y_enc = le.fit_transform(y_live)
                    live_clf = Pipeline([
                        ("scaler", StandardScaler()),
                        ("gb", HistGradientBoostingClassifier(random_state=42)),
                    ])
                    
                    n_cv = min(3, len(X_live) // 5) if len(X_live) > 10 else 2
                    if n_cv >= 2:
                        param_dist = {
                            "gb__learning_rate": [0.05, 0.1, 0.2],
                            "gb__max_iter": [100, 200, 300],
                            "gb__max_depth": [3, 5, 10, None]
                        }
                        search = RandomizedSearchCV(live_clf, param_dist, n_iter=5, cv=n_cv, n_jobs=2, random_state=42)
                        search.fit(X_live, y_enc)
                        self.live_pipeline = search.best_estimator_
                        result["live_best_params"] = search.best_params_
                        logger.info(f"Live classifier optimized: {search.best_params_}")
                    else:
                        live_clf.fit(X_live, y_enc)
                        self.live_pipeline = live_clf
                        logger.info("Not enough data for CV, used default HistGradientBoosting.")

                    self.live_classes = list(le.classes_)
                    self.live_supervised = True
                    result["live_samples"] = len(X_live)
                    result["live_classes"] = self.live_classes
                    logger.info(f"Live classifier trained on {len(X_live)} samples")
                else:
                    logger.info(f"Only 1 class in live logs ({unique_classes}) — skipping live classifier")

        # 3. IsolationForest fallback (trains on whatever we have)
        if live_logs:
            X_all = extract_features(live_logs)
            
            anomalies_count = 0
            for log in live_logs:
                cat = str(log.get("threat_category", "")).lower()
                et = str(log.get("event_type", "")).lower()
                family = THREAT_CAT_MAP.get(cat) or THREAT_CAT_MAP.get(et, "normal")
                if family != "normal":
                    anomalies_count += 1
            
            dynamic_contam = max(0.01, min(0.2, anomalies_count / max(1, len(live_logs))))
            logger.info(f"Dynamic contamination calculated as {dynamic_contam:.3f} based on {anomalies_count} anomalies out of {len(live_logs)} logs")

            iforest = Pipeline([
                ("scaler", StandardScaler()),
                ("iforest", IsolationForest(n_estimators=200, contamination=dynamic_contam,
                                             max_samples="auto", random_state=42, n_jobs=2)),
            ])
            iforest.fit(X_all)
            self.if_pipeline = iforest
            result["if_samples"] = len(live_logs)
            result["if_contamination"] = dynamic_contam
        elif self.if_pipeline is None:
            X_synth = _synthetic_normal(500)
            iforest = Pipeline([
                ("scaler", StandardScaler()),
                ("iforest", IsolationForest(n_estimators=100, contamination=CONTAMINATION,
                                             random_state=42, n_jobs=2)),
            ])
            iforest.fit(X_synth)
            self.if_pipeline = iforest
            result["if_bootstrapped"] = True

        self.trained_at = datetime.now(timezone.utc)
        self.training_samples = len(live_logs) + (len(nsl[0]) if nsl else 0)
        result["trained_at"] = self.trained_at.isoformat()

        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "rf_pipeline":   self.rf_pipeline,
            "live_pipeline": self.live_pipeline,
            "if_pipeline":   self.if_pipeline,
            "rf_classes":    self.rf_classes,
            "live_classes":  self.live_classes,
            "trained_at":    self.trained_at,
            "training_samples": self.training_samples,
            "nsl_kdd_trained":  self.nsl_kdd_trained,
            "live_supervised":  self.live_supervised,
        }, MODEL_PATH)

        return {"success": True, **result}

    def evaluate(self) -> dict:
        from sklearn.metrics import accuracy_score, classification_report
        if self.rf_pipeline is None:
            return {"error": "RF model not trained yet"}
        if not _download_file(NSL_KDD_TEST_URL, NSL_KDD_TEST_PATH):
            return {"error": "Failed to download KDDTest+.txt"}
        result = _parse_nsl_kdd_raw(NSL_KDD_TEST_PATH)
        if result is None:
            return {"error": "Failed to parse test set"}
        X_test_all, y_strings = result
        class_to_idx = {c: i for i, c in enumerate(self.rf_classes)}
        X_valid, y_valid = [], []
        for i, label in enumerate(y_strings):
            idx = class_to_idx.get(label)
            if idx is not None:
                X_valid.append(X_test_all[i])
                y_valid.append(idx)
        X_valid = np.array(X_valid, dtype=np.float32)
        y_valid = np.array(y_valid)
        y_pred = self.rf_pipeline.predict(X_valid)
        acc = accuracy_score(y_valid, y_pred)
        report = classification_report(y_valid, y_pred,
                                       labels=list(range(len(self.rf_classes))),
                                       target_names=self.rf_classes,
                                       output_dict=True, zero_division=0)
        per_class = {
            cls: {"precision": round(report[cls]["precision"], 3),
                  "recall": round(report[cls]["recall"], 3),
                  "f1": round(report[cls]["f1-score"], 3),
                  "support": int(report[cls]["support"])}
            for cls in self.rf_classes if cls in report
        }
        return {
            "accuracy": round(float(acc), 4),
            "test_samples": len(y_valid),
            "skipped_samples": len(y_strings) - len(y_valid),
            "per_class": per_class,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

    def predict(self, logs: list[dict]) -> list[dict]:
        if not self.is_trained():
            return []

        X = extract_features(logs)
        if_preds  = self.if_pipeline.predict(X) if self.if_pipeline else np.ones(len(logs))
        if_scores = self.if_pipeline.decision_function(X) if self.if_pipeline else np.zeros(len(logs))

        # Zero-shot classification (batch)
        zs_results = []
        if self.zs_classifier and self.zs_classifier.available:
            texts = [log_to_text(log) for log in logs]
            zs_results = self.zs_classifier.classify(texts)

        results = []
        for i, (log, if_pred, if_score) in enumerate(zip(logs, if_preds, if_scores)):
            # IF only counts as anomaly signal if score meaningful (eliminates near-zero noise)
            is_if_anomaly = if_pred == -1 and if_score < -0.08

            # Layer 1: direct label from threat_category / event_type fields
            # (simulator already labels logs — use it as highest-confidence signal)
            label_class, label_conf = _infer_from_labels(log)
            is_label_attack = label_class != "normal" and label_conf >= 0.9

            # Layer 2: live GradientBoosting (9-feature, trained on labeled ES logs)
            live_class, live_conf = "unknown", 0.0
            if self.live_pipeline is not None:
                try:
                    proba = self.live_pipeline.predict_proba(X[i:i+1])[0]
                    live_idx = int(np.argmax(proba))
                    live_class = self.live_classes[live_idx] if live_idx < len(self.live_classes) else "unknown"
                    live_conf = float(proba[live_idx])
                except Exception:
                    pass
            is_live_attack = live_class != "normal" and live_conf > 0.65

            # Layer 3: zero-shot NLI
            zs = zs_results[i] if i < len(zs_results) else {}
            zs_class = zs.get("rf_class", "unknown_anomaly")
            zs_score = zs.get("score", 0.0)
            zs_label = zs.get("label", "")
            is_zs_attack = zs_class != "normal" and zs_score > 0.6

            is_anomaly = is_label_attack or is_live_attack or is_zs_attack or is_if_anomaly

            if is_anomaly:
                # Priority: label > live GB > zero-shot > IF
                if is_label_attack:
                    final_class, final_conf = label_class, label_conf
                elif is_live_attack:
                    final_class, final_conf = live_class, live_conf
                elif is_zs_attack:
                    final_class, final_conf = zs_class, zs_score
                else:
                    final_class, final_conf = "unknown_anomaly", 0.5

                severity = _determine_severity(final_class, final_conf, if_score, is_if_anomaly)
                explanation = _explain(
                    log, X[i], if_score, label_class, label_conf,
                    live_class, live_conf, zs_label, zs_score,
                    is_if_anomaly, is_label_attack, is_live_attack, is_zs_attack,
                )
                result_dict = {
                    **log,
                    "ml_anomaly": True,
                    "ml_if_score": round(float(if_score), 4),
                    "ml_rf_class": final_class,
                    "ml_rf_confidence": round(final_conf, 3),
                    "ml_rf_top_classes": {},
                    "ml_live_class": live_class,
                    "ml_live_confidence": round(live_conf, 3),
                    "ml_zs_label": zs_label,
                    "ml_zs_score": round(zs_score, 3),
                    "ml_severity": severity,
                    "ml_explanation": explanation,
                    "ml_detected_at": datetime.now(timezone.utc).isoformat(),
                    "ml_score": round(float(if_score), 4),
                    "ml_src_geo": _get_geo(log.get("src_ip", "")),
                    "ml_dst_geo": _get_geo(log.get("dst_ip", "")),
                    "detection_method": "ml",
                }
                
                # Add MITRE techniques
                mitre_list = []
                evt = str(log.get("event_type", "")).lower()
                fallback_map = {
                    "port_scan": "T1046", "brute_force": "T1110", "lateral_movement": "T1021.002",
                    "data_exfil": "T1041", "c2_beacon": "T1071", "recon": "T1018",
                    "dos": "T1498"
                }
                if evt in fallback_map:
                    mitre_list.append(fallback_map[evt])
                elif final_class == "dos":
                    mitre_list.append("T1498")
                elif final_class == "probe":
                    mitre_list.append("T1046")
                elif final_class == "r2l":
                    mitre_list.append("T1110")
                elif final_class == "u2r":
                    mitre_list.append("T1068")
                
                result_dict["mitre_techniques"] = mitre_list
                
                if self.narrator.available:
                    narrative = self.narrator.narrate(result_dict)
                    if narrative:
                        result_dict["ml_explanation"] = narrative
                        
                results.append(result_dict)

        return results


# Direct mapping from event_type / threat_category → attack family
# Not a rule engine — uses labeled fields the simulator already sets as ground truth
_EVENT_TO_CLASS = {
    "port_scan": "probe", "recon": "probe", "ipsweep": "probe", "nmap": "probe",
    "brute_force": "r2l", "lateral_movement": "r2l", "ftp_write": "r2l",
    "guess_passwd": "r2l", "ssh": "r2l",
    "data_exfil": "u2r", "c2_beacon": "u2r", "privesc": "u2r",
    "dos": "dos", "ddos": "dos", "neptune": "dos", "smurf": "dos",
    "normal": "normal", "dns": "normal", "http": "normal",
    "https": "normal", "ntp": "normal", "smtp": "normal",
    "syscheck": "u2r", "rootcheck": "u2r", "sca": "probe", "localfile": "u2r",
}


def _infer_from_labels(log: dict) -> tuple[str, float]:
    """Infer attack class from pre-labeled fields (threat_category, event_type).
    Returns (class, confidence). Confidence=1.0 when label is definitive."""
    cat = log.get("threat_category", "")
    if isinstance(cat, list):
        cat = cat[0]
    cat = str(cat).lower().strip()
    
    et = log.get("event_type", "")
    if isinstance(et, list):
        et = et[0]
    et = str(et).lower().strip()

    # First, if event_type explicitly maps to an attack (e.g. syscheck, rootcheck, localfile), prioritize it
    et_cls = _EVENT_TO_CLASS.get(et)
    if et_cls and et_cls != "normal":
        return et_cls, 0.95

    # Then check threat_category
    cls = THREAT_CAT_MAP.get(cat) or _EVENT_TO_CLASS.get(cat)
    if cls and cls != "normal":
        return cls, 1.0
    if cls == "normal":
        return "normal", 1.0

    if et_cls == "normal":
        return "normal", 0.95

    return "unknown", 0.0


def _determine_severity(rf_class: str, rf_conf: float, if_score: float, is_if: bool) -> str:
    if rf_class in ("u2r", "r2l") and rf_conf > 0.7:
        return "critical"
    if rf_class == "dos" and rf_conf > 0.7:
        return "high"
    if rf_class == "probe" and rf_conf > 0.6:
        return "medium"
    if is_if and if_score < -0.3:
        return "critical"
    if is_if and if_score < -0.15:
        return "high"
    if is_if and if_score < -0.05:
        return "medium"
    return "low"


def _explain(log, X, if_score, label_class, _label_conf,
             live_class, live_conf, zs_label, zs_score,
             is_if, is_label, is_live, is_zs) -> str:
    parts = []
    
    desc = log.get("wazuh_description") or log.get("rule", {}).get("description") or log.get("event_type")
    if desc:
        parts.append(f"Event: {desc}")
        
    if is_label:
        parts.append(f"Rule match: {label_class.upper()}")
    if is_live:
        parts.append(f"ML Classifier: {live_class.upper()} ({live_conf:.0%} conf)")
    if is_zs:
        parts.append(f"AI match: \"{zs_label}\" ({zs_score:.0%})")
    if is_if:
        parts.append(f"Anomaly score: {if_score:.3f}")
        bytes_val = X[FEATURE_NAMES.index("bytes")]
        if bytes_val > 100000:
            parts.append(f"Large transfer ({bytes_val/1024:.0f}KB)")
        if X[FEATURE_NAMES.index("is_external_dst")]:
            parts.append("Destination is external")
            
    return " | ".join(parts) if parts else "Anomaly detected"


def _synthetic_normal(n: int) -> np.ndarray:
    import random as _r
    rows = []
    for _ in range(n):
        rows.append([
            _r.randint(0, 23), _r.randint(200, 50000),
            _r.choice([80, 443, 53, 123]), _r.randint(1024, 65535),
            _r.choice([0, 1]), _r.choice([0, 1, 2, 3]), 1, 0, 1,
        ])
    return np.array(rows, dtype=np.float32)
