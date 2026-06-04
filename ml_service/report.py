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
    """Build a professional aggregate intelligence report for the dashboard."""
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).isoformat()

    # ── 1. Pull data from ES ──────────────────────────────────────────────────

    # Total log count
    total_logs = es_client.count(index="syndicate4-logs-*")["count"]

    # Alert summary by severity
    sev_agg = es_client.search(
        index="syndicate4-ml-alerts",
        body={
            "query": {"range": {"ml_detected_at": {"gte": since}}},
            "size": 0,
            "aggs": {
                "by_sev": {"terms": {"field": "ml_severity.keyword", "size": 10}},
            },
        },
    )
    sev_buckets = {b["key"]: b["doc_count"]
                   for b in sev_agg["aggregations"]["by_sev"]["buckets"]}
    total_alerts = sev_agg["hits"]["total"]["value"]

    # Alert timeline (hourly buckets)
    timeline_agg = es_client.search(
        index="syndicate4-ml-alerts",
        body={
            "query": {"range": {"ml_detected_at": {"gte": since}}},
            "size": 0,
            "aggs": {
                "by_hour": {
                    "date_histogram": {
                        "field": "ml_detected_at",
                        "calendar_interval": "1h",
                        "min_doc_count": 0,
                        "extended_bounds": {"min": since, "max": now.isoformat()},
                    }
                }
            },
        },
    )
    hourly = [(b["key_as_string"][11:16], b["doc_count"])
              for b in timeline_agg["aggregations"]["by_hour"]["buckets"]]

    # MITRE technique hits
    mitre_agg = es_client.search(
        index="syndicate4-ml-alerts",
        body={
            "query": {"range": {"ml_detected_at": {"gte": since}}},
            "size": 0,
            "aggs": {"by_mitre": {"terms": {"field": "mitre_technique.keyword", "size": 20}}},
        },
    )
    mitre_hits = [(b["key"], b["doc_count"])
                  for b in mitre_agg["aggregations"]["by_mitre"]["buckets"]]

    # Attack class distribution
    class_agg = es_client.search(
        index="syndicate4-ml-alerts",
        body={
            "query": {"range": {"ml_detected_at": {"gte": since}}},
            "size": 0,
            "aggs": {"by_class": {"terms": {"field": "ml_rf_class.keyword", "size": 10}}},
        },
    )
    class_hits = [(b["key"], b["doc_count"])
                  for b in class_agg["aggregations"]["by_class"]["buckets"]]

    # Top source IPs
    ip_agg = es_client.search(
        index="syndicate4-ml-alerts",
        body={
            "query": {"range": {"ml_detected_at": {"gte": since}}},
            "size": 0,
            "aggs": {"by_ip": {"terms": {"field": "src_ip.keyword", "size": 10}}},
        },
    )
    top_ips = [(b["key"], b["doc_count"])
               for b in ip_agg["aggregations"]["by_ip"]["buckets"]]

    # Top event types
    etype_agg = es_client.search(
        index="syndicate4-ml-alerts",
        body={
            "query": {"range": {"ml_detected_at": {"gte": since}}},
            "size": 0,
            "aggs": {"by_type": {"terms": {"field": "event_type.keyword", "size": 10}}},
        },
    )
    top_types = [(b["key"], b["doc_count"])
                 for b in etype_agg["aggregations"]["by_type"]["buckets"]]

    # Recent critical alerts
    recent = es_client.search(
        index="syndicate4-ml-alerts",
        body={
            "query": {
                "bool": {
                    "must": [{"range": {"ml_detected_at": {"gte": since}}}],
                    "should": [{"term": {"ml_severity.keyword": "critical"}},
                               {"term": {"ml_severity.keyword": "high"}}],
                    "minimum_should_match": 1,
                }
            },
            "size": 30,
            "sort": [{"ml_detected_at": {"order": "desc"}}],
        },
    )
    recent_alerts = [h["_source"] for h in recent["hits"]["hits"]]

    # ── 2. Build PDF ──────────────────────────────────────────────────────────
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
    pdf.cell(0, 6, "AI-Based Cyber Threat Detection — Threat Intelligence Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 5, f"Period: last {hours}h  |  Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}",
             align="C", ln=True)
    pdf.ln(18)

    # ── Executive summary ─────────────────────────────────────────────────────
    pdf.section("EXECUTIVE SUMMARY")
    pdf.kv_row("Total logs in ES",     f"{total_logs:,}")
    pdf.kv_row(f"Alerts (last {hours}h)", f"{total_alerts:,}")
    pdf.kv_row("Critical",  str(sev_buckets.get("critical", 0)), C_RED)
    pdf.kv_row("High",      str(sev_buckets.get("high", 0)),     C_YELLOW)
    pdf.kv_row("Medium",    str(sev_buckets.get("medium", 0)),   C_PURPLE)
    pdf.kv_row("Low",       str(sev_buckets.get("low", 0)),      C_DIM)
    pdf.kv_row("Report period", f"{since[:10]} to {now.strftime('%Y-%m-%d')}")

    # ── Alert timeline ────────────────────────────────────────────────────────
    if hourly:
        pdf.section(f"ALERT TIMELINE (last {hours}h - hourly)")
        max_h = max(c for _, c in hourly) if hourly else 1
        graph_h = 40
        graph_w = 170
        x0, y0 = 14, pdf.get_y()
        col_w = graph_w / max(len(hourly), 1)

        # background
        pdf.set_fill_color(*C_PANEL)
        pdf.rect(x0, y0, graph_w, graph_h, "F")

        for i, (label, cnt) in enumerate(hourly):
            bh = int((cnt / max(max_h, 1)) * (graph_h - 6))
            bx = x0 + i * col_w + 1
            by = y0 + graph_h - bh - 1
            color = C_RED if cnt > (max_h * 0.7) else C_YELLOW if cnt > (max_h * 0.3) else C_ACCENT
            pdf.set_fill_color(*color)
            if bh > 0:
                pdf.rect(bx, by, max(col_w - 2, 1), bh, "F")

        # x-axis labels (every 4h)
        pdf.set_font("Helvetica", "", 5)
        pdf.set_text_color(*C_DIM)
        for i, (label, _) in enumerate(hourly):
            if i % 4 == 0:
                pdf.set_xy(x0 + i * col_w, y0 + graph_h + 1)
                pdf.cell(col_w * 4, 4, label)

        pdf.set_y(y0 + graph_h + 6)

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    if mitre_hits:
        pdf.section("MITRE ATT&CK TECHNIQUE HITS")
        total_m = sum(c for _, c in mitre_hits)
        for tid, cnt in mitre_hits[:15]:
            pdf.bar(tid, cnt, total_m, C_ACCENT)

    # ── Attack class breakdown ────────────────────────────────────────────────
    if class_hits:
        pdf.section("RF ATTACK CLASSIFICATION")
        total_c = sum(c for _, c in class_hits)
        for cls, cnt in class_hits:
            pdf.bar(cls.upper(), cnt, total_c, CLASS_COLOR.get(cls, C_DIM))

    # ── Top event types ───────────────────────────────────────────────────────
    if top_types:
        pdf.section("TOP EVENT TYPES")
        total_t = sum(c for _, c in top_types)
        for etype, cnt in top_types[:10]:
            pdf.bar(etype, cnt, total_t, C_PURPLE)

    # ── Top source IPs ────────────────────────────────────────────────────────
    if top_ips:
        pdf.section("TOP SOURCE IPs (alerts)")
        total_i = sum(c for _, c in top_ips)
        for ip, cnt in top_ips[:10]:
            pdf.bar(ip, cnt, total_i, C_RED)

    # ── Recent critical/high alerts ───────────────────────────────────────────
    if recent_alerts:
        pdf.section("RECENT CRITICAL / HIGH ALERTS")
        col_widths = [22, 18, 35, 22, 32, 20]
        headers    = ["Time", "Severity", "Event Type", "MITRE", "Src IP", "Score"]

        # header row
        pdf.set_fill_color(*C_PANEL)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*C_ACCENT)
        for w, h in zip(col_widths, headers):
            pdf.cell(w, 5, h, border=0, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 7)
        for i, a in enumerate(recent_alerts[:25]):
            sev = a.get("ml_severity", "low")
            if i % 2 == 0:
                pdf.set_fill_color(*C_PANEL)
            else:
                pdf.set_fill_color(*C_BG)

            row = [
                (a.get("ml_detected_at") or a.get("timestamp") or "")[:19].replace("T", " ")[11:],
                sev.upper(),
                (a.get("event_type") or "-")[:22],
                a.get("mitre_technique") or "-",
                (a.get("src_ip") or "-")[:20],
                f"{a.get('ml_score', 0):.3f}",
            ]
            pdf.set_text_color(*SEV_COLOR.get(sev, C_DIM) if row[1] != "-" else C_DIM)
            pdf.cell(col_widths[0], 5, row[0], fill=True)
            pdf.set_text_color(*SEV_COLOR.get(sev, C_WHITE))
            pdf.cell(col_widths[1], 5, row[1], fill=True)
            pdf.set_text_color(*C_WHITE)
            for w, v in zip(col_widths[2:], row[2:]):
                pdf.cell(w, 5, v, fill=True)
            pdf.ln()

    # ── Forensics / AI Reasoning ──────────────────────────────────────────────
    if recent_alerts:
        pdf.add_page()
        pdf.section("FORENSICS & AI REASONING (Deep Dive)")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*C_DIM)
        pdf.multi_cell(0, 4, "Detailed analysis of top threats using the hybrid ML pipeline (IsolationForest + Random Forest + Zero-Shot NLI).", ln=True)
        pdf.ln(2)

        for i, a in enumerate(recent_alerts[:15]):
            pdf.set_fill_color(*C_PANEL)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*C_ACCENT)
            time_str = (a.get("ml_detected_at") or "")[11:19]
            pdf.cell(0, 6, f" {time_str} | {a.get('event_type','unknown').upper()} | {a.get('ml_rf_class','anomaly').upper()}", fill=True, ln=True)
            
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C_WHITE)
            pdf.ln(1)
            pdf.set_text_color(*C_WHITE)
            pdf.cell(35, 4, "Explanation:", ln=False)
            pdf.set_text_color(*C_DIM)
            pdf.multi_cell(145, 4, a.get("ml_explanation", "No explanation provided."), ln=True)
            
            pdf.set_text_color(*C_WHITE)
            pdf.cell(30, 4, "Connectivity:", ln=False)
            pdf.set_text_color(*C_DIM)
            src_geo = a.get("ml_src_geo", "Unknown")
            dst_geo = a.get("ml_dst_geo", "Unknown")
            pdf.cell(0, 4, f"{a.get('src_ip','-')} ({src_geo}) -> {a.get('dst_ip','-')} ({dst_geo}) port {a.get('dst_port','-')}", ln=True)
            
            pdf.ln(2)
            if i >= 14: break

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
