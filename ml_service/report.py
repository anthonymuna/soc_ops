"""Server-side PDF report generator - queries ES directly."""

from datetime import datetime, timezone, timedelta
from fpdf import FPDF
from elasticsearch import Elasticsearch

# ── colours ────────────────────────────────────────────────────────────────────
# ── colours (Professional Light Mode) ──────────────────────────────────────────
C_BG       = (255, 255, 255)
C_PANEL    = (248, 250, 252)
C_ACCENT   = (15,  23,  42)
C_TEXT     = (30,  41,  59)
C_WHITE    = (255, 255, 255)
C_DIM      = (100, 116, 139)
C_RED      = (220, 38,  38)
C_YELLOW   = (234, 179,   8)
C_GREEN    = (22, 163,  74)
C_PURPLE   = (124,  58, 237)
C_ORANGE   = (234, 88,   12)
C_BORDER   = (226, 232, 240)

SEV_COLOR  = {
    "critical": C_RED,
    "high":     C_YELLOW,
    "medium":   C_PURPLE,
    "low":      C_DIM,
}

CLASS_COLOR = {
    "dos":          C_RED,
    "probe":        C_YELLOW,
    "r2l":          C_ORANGE,
    "u2r":          (220, 38, 38),
    "normal":       C_GREEN,
    "unclassified": C_DIM,
}


class SocPDF(FPDF):
    def __init__(self, hours: int):
        super().__init__()
        self.hours = hours
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_fill_color(*C_PANEL)
        self.rect(0, 0, 210, 14, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_DIM)
        self.cell(0, 14, "NGAO SOC  |  THREAT INTELLIGENCE  |  CONFIDENTIAL", align="C")
        self.ln(4)

    def footer(self):
        self.set_y(-10)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_DIM)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    # ── helpers ────────────────────────────────────────────────────────────────
    def section(self, title: str):
        self.ln(4)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 6, title, ln=True)
        self.set_draw_color(*C_BORDER)
        self.set_line_width(0.3)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(3)

    def gauge(self, label: str, value: float, color: tuple):
        """Draw a visual risk gauge (0.0 to 1.0)."""
        x, y = self.get_x(), self.get_y()
        w, h = 40, 4
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*C_DIM)
        self.cell(30, 5, label, ln=False)
        
        # bar background
        self.set_fill_color(241, 245, 249)
        self.rect(x + 30, y + 1, w, h, "F")
        # bar fill
        self.set_fill_color(*color)
        self.rect(x + 30, y + 1, w * value, h, "F")
        
        self.set_x(x + 30 + w + 3)
        self.set_text_color(*color)
        self.cell(0, 5, f"{value*100:.1f}%", ln=True)

    def kv_row(self, key: str, value: str, val_color=None):
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*C_DIM)
        self.cell(60, 5, key, ln=False)
        self.set_text_color(*(val_color or C_TEXT))
        self.cell(0, 5, str(value), ln=True)

    def bar(self, label: str, count: int, total: int, color: tuple, w: float = 120):
        pct = count / max(total, 1)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_TEXT)
        self.cell(35, 5, label[:20], ln=False)
        # background
        x, y = self.get_x(), self.get_y()
        self.set_fill_color(*C_PANEL)
        self.rect(x, y + 1, w, 3, "F")
        # fill
        self.set_fill_color(*color)
        self.rect(x, y + 1, max(w * pct, 0.5), 3, "F")
        self.set_x(x + w + 2)
        self.set_text_color(*C_DIM)
        self.cell(0, 5, f"{count:,}  ({pct*100:.1f}%)", ln=True)


# ── main build function ────────────────────────────────────────────────────────

def build_report(es_client: Elasticsearch, hours: int = 24) -> bytes:
    """Build a professional 2-paragraph aggregate intelligence report."""
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).isoformat()

    # Total logs
    try:
        total_logs = es_client.count(index="syndicate4-logs-*")["count"]
    except Exception:
        total_logs = 0

    # Alerts by severity, mitre, class, ip
    try:
        sev_agg = es_client.search(
            index="syndicate4-ml-alerts",
            body={
                "query": {"range": {"ml_detected_at": {"gte": since}}},
                "size": 0,
                "aggs": {
                    "by_sev": {"terms": {"field": "ml_severity.keyword", "size": 10}},
                    "by_mitre": {"terms": {"field": "mitre_technique.keyword", "size": 5}},
                    "by_class": {"terms": {"field": "ml_rf_class.keyword", "size": 5}},
                    "by_ip": {"terms": {"field": "src_ip.keyword", "size": 5}}
                },
            },
        )
        total_alerts = sev_agg["hits"]["total"]["value"]
        aggs = sev_agg.get("aggregations", {})
        sev_buckets = {b["key"]: b["doc_count"] for b in aggs.get("by_sev", {}).get("buckets", [])}
        mitre_hits = [b["key"] for b in aggs.get("by_mitre", {}).get("buckets", []) if b["key"] != "normal"]
        class_hits = [b["key"] for b in aggs.get("by_class", {}).get("buckets", []) if b["key"] != "normal"]
        top_ips = [b["key"] for b in aggs.get("by_ip", {}).get("buckets", [])]
    except Exception:
        total_alerts = 0
        sev_buckets = {}
        mitre_hits = []
        class_hits = []
        top_ips = []

    mitre_names_dict = {
        "T1046": "Network Scanning", 
        "T1110": "Brute Force", 
        "T1110.001": "Password Guessing",
        "T1021": "Lateral Movement", 
        "T1021.002": "SMB Lateral Movement",
        "T1041": "Data Exfiltration", 
        "T1071": "C2 Beaconing", 
        "T1018": "Reconnaissance",
        "T1049": "Network Discovery", 
        "T1057": "Process Discovery", 
        "T1082": "System Info Discovery",
        "T1083": "File Discovery", 
        "T1105": "Tool Transfer", 
        "T1059": "Malicious Execution",
        "T1498": "Denial of Service (DoS)", 
        "T1498.001": "SYN Flood", 
        "T1190": "Exploiting Public-Facing Application",
        "T1048": "Exfiltration Over Alternative Protocol", 
        "T1068": "Privilege Escalation", 
        "T1571": "Non-Standard Port Usage",
        "T1078": "Valid Accounts"
    }

    crit_high = sev_buckets.get("critical", 0) + sev_buckets.get("high", 0)
    class_str = ", ".join(class_hits).upper() if class_hits else "various anomalous activities"
    mitre_names = [mitre_names_dict.get(k, k) for k in mitre_hits]
    mitre_str = ", ".join(mitre_names) if mitre_names else "multiple vectors"
    ip_str = ", ".join(top_ips) if top_ips else "unknown sources"

    p1 = (f"Over the past {hours} hours, the NGAO SOC AI Engine analyzed {total_logs:,} events and detected "
          f"{total_alerts:,} security alerts, including {crit_high} critical or high severity threats. "
          f"The primary threat classifications identified were {class_str}, utilizing MITRE ATT&CK techniques "
          f"such as {mitre_str}. The majority of these malicious activities originated from source IPs: {ip_str}, "
          f"indicating targeted or automated scanning and exploitation attempts against the network infrastructure.")

    recs = []
    if "dos" in class_hits or "flood" in class_str.lower():
        recs.append("implementing strict rate limiting and enabling DDoS protection on edge routers")
    if "probe" in class_hits or "recon" in mitre_str.lower() or "discovery" in mitre_str.lower():
        recs.append("blocking persistent scanning IPs at the firewall and auditing external exposed services")
    if "r2l" in class_hits or "valid accounts" in mitre_str.lower() or "brute force" in mitre_str.lower():
        recs.append("enforcing Multi-Factor Authentication (MFA) and reviewing recent failed login thresholds")
    if "u2r" in class_hits or "privilege escalation" in mitre_str.lower() or "execution" in mitre_str.lower():
        recs.append("isolating affected internal hosts immediately and rotating administrative credentials")
    
    if not recs:
        recs = ["monitoring anomalous IP traffic", "validating security group rules", "ensuring all systems are fully patched"]
        
    if len(recs) > 1:
        recs_str = ", ".join(recs[:-1]) + ", and " + recs[-1]
    else:
        recs_str = recs[0]

    p2 = (f"To mitigate these identified threats and secure the environment, it is strongly recommended to "
          f"take immediate action by {recs_str}. Furthermore, security teams should "
          f"review the specific alerts associated with the high-risk IPs ({ip_str}) to identify compromised accounts "
          f"or internal lateral movement, ensuring that baseline network access policies are strictly enforced.")

    pdf = SocPDF(hours)
    pdf.add_page()
    
    # Cover / title block
    pdf.set_fill_color(*C_BG)
    pdf.rect(0, 14, 210, 40, "F")
    pdf.set_y(20)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*C_ACCENT)
    pdf.cell(0, 10, "NGAO SOC", align="C", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_DIM)
    pdf.cell(0, 6, "AI-Based Cyber Threat Detection - Executive Summary Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 5, f"Period: last {hours}h  |  Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}",
             align="C", ln=True)
    pdf.ln(18)

    pdf.section("THREAT INTELLIGENCE SUMMARY")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_TEXT)
    pdf.multi_cell(0, 6, p1)
    pdf.ln(4)

    pdf.section("RECOMMENDATIONS")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_TEXT)
    pdf.multi_cell(0, 6, p2)
    
    return bytes(pdf.output())


def build_incident_report(alert: dict) -> bytes:
    """Build a detailed, single-incident threat intelligence report."""
    now = datetime.now(timezone.utc)
    pdf = SocPDF(hours=0) # Hours not used for single report
    pdf.add_page()
    
    # ── Header ────────────────────────────────────────────────────────────────
    pdf.set_y(18)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*C_RED)
    pdf.cell(0, 10, "THREAT INTELLIGENCE REPORT", align="C", ln=True)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C_DIM)
    pdf.cell(0, 6, f"Incident ID: {str(alert.get('id', 'UNK'))[:12]} | Confirmed THREAT", align="C", ln=True)
    pdf.ln(10)

    # ── Executive Summary ─────────────────────────────────────────────────────
    pdf.section("EXECUTIVE SUMMARY")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_TEXT)
    
    summary = (
        f"A confirmed security incident was identified on {alert.get('ml_detected_at', 'N/A')}. "
        f"The Syndicate 4 AI engine detected an anomaly from source host {alert.get('src_ip', 'Unknown')} "
        f"targeting {alert.get('dst_ip', 'Unknown')}. This event was classified as {alert.get('ml_rf_class', 'anomaly').upper()} "
        f"with an AI confidence level of {alert.get('ml_rf_confidence', 0)*100:.1f}%."
    )
    pdf.multi_cell(180, 5, summary)
    pdf.ln(5)

    # Risk Metrics (Visual Graphics)
    pdf.gauge("Threat Confidence", alert.get("ml_rf_confidence", 0), C_PURPLE)
    sev_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
    sev_val = sev_map.get(alert.get("ml_severity", "low"), 0.1)
    pdf.gauge("Impact Severity", sev_val, SEV_COLOR.get(alert.get("ml_severity", "low"), C_RED))
    pdf.ln(4)

    # ── Incident Context ──────────────────────────────────────────────────────
    pdf.section("INCIDENT CONTEXT")
    pdf.kv_row("Detection Timestamp", alert.get("ml_detected_at", "-"))
    pdf.kv_row("Primary Classification", alert.get("ml_rf_class", "anomaly").upper(), C_RED)
    pdf.kv_row("Source Node", f"{alert.get('src_ip','-')} ({alert.get('ml_src_geo','Unknown')})")
    pdf.kv_row("Target Node", f"{alert.get('dst_ip','-')} ({alert.get('ml_dst_geo','Unknown')})")
    pdf.kv_row("Protocol / Port", f"{alert.get('protocol','tcp').upper()} / {alert.get('dst_port', '-')}")
    pdf.kv_row("MITRE ATT&CK", alert.get("mitre_technique", "N/A"), C_YELLOW)

    # ── AI Technical Evidence ──────────────────────────────────────────────────
    pdf.section("FORENSIC EVIDENCE & AI REASONING")
    
    # Reasoning text
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*C_ACCENT)
    pdf.cell(0, 5, "Neural Engine Logic:", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C_TEXT)
    pdf.multi_cell(180, 5, alert.get("ml_explanation", "Detailed AI reasoning is being synthesized for this event."))
    pdf.ln(5)

    # Feature Table
    pdf.set_fill_color(*C_PANEL)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*C_ACCENT)
    pdf.cell(90, 7, "  Metric / Feature Name", fill=True)
    pdf.cell(90, 7, "  Value", fill=True)
    pdf.ln()
    
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*C_TEXT)
    
    features = alert.get("ml_features", {})
    if not features:
        # Fallback evidence if features dictionary is missing
        features = {
            "Bytes Inbound": f"{alert.get('bytes', 0):,}",
            "Connection Count": str(alert.get("connection_count", "1")),
            "Anomaly Score": f"{alert.get('ml_score', 0):.4f}",
            "Zero-Shot Label": alert.get("ml_zs_label", "N/A"),
            "Protocol State": alert.get("state", "FIN"),
        }
    
    for k, v in features.items():
        pdf.set_draw_color(*C_BORDER)
        pdf.cell(90, 6, f"  {k}", border="B")
        pdf.cell(90, 6, f"  {v}", border="B")
        pdf.ln()
    
    # ── Remediation ──────────────────────────────────────────────────────────
    pdf.section("RECOMMENDED REMEDIATION ACTIONS")
    
    actions = {
        "dos": [
            "2. Verify if the target service is under resource exhaustion.",
            "3. Enable DDoS protection features on the WAF/Load Balancer."
        ],
        "probe": [
            "1. Block the source IP temporarily to prevent further reconnaissance.",
            "2. Review firewall logs for other suspicious scanning activity from the same subnet.",
            "3. Ensure all exposed services are patched and up-to-date."
        ],
        "r2l": [
            "1. Terminate any active sessions originating from the source IP.",
            "2. Reset passwords for any accounts that may have been targeted by brute force.",
            "3. Enable Multi-Factor Authentication (MFA) for the targeted service."
        ],
        "u2r": [
            "1. ISOLATE the affected host from the network immediately.",
            "2. Perform a full forensic memory dump and disk image for investigation.",
            "3. Revoke all administrative credentials until the breach is contained."
        ],
        "anomaly": [
            "1. Monitor the source IP for further unusual behavior.",
            "2. Validate the traffic against known baseline network patterns.",
            "3. Review the logs in Kibana for associated events in the same time window."
        ]
    }
    
    rec_list = actions.get(alert.get("ml_rf_class", "anomaly"), actions["anomaly"])
    for action in rec_list:
        pdf.multi_cell(180, 5, action)
    
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(*C_DIM)
    pdf.cell(0, 5, f"Report Generated by NGAO SOC AI Engine at {now.strftime('%Y-%m-%d %H:%M:%S UTC')}", align="C")

    return bytes(pdf.output())
