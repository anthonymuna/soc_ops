"""Server-side PDF report generator - queries ES directly."""

from datetime import datetime, timezone, timedelta
from fpdf import FPDF

# ── colours ────────────────────────────────────────────────────────────────────
C_BG       = (10,  14,  26)
C_PANEL    = (15,  22,  41)
C_ACCENT   = (0,  212, 255)
C_WHITE    = (226, 232, 240)
C_DIM      = (100, 116, 139)
C_RED      = (255,  51, 102)
C_YELLOW   = (255, 170,   0)
C_GREEN    = (0,  255, 136)
C_PURPLE   = (124,  58, 237)
C_ORANGE   = (249, 115,  22)

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
        self.set_auto_page_break(auto=True, margin=14)

    def header(self):
        self.set_fill_color(*C_PANEL)
        self.rect(0, 0, 210, 14, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 14, "SYNDICATE4  ·  AI CYBER THREAT DETECTION  ·  CONFIDENTIAL", align="C")
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
        self.set_draw_color(*C_ACCENT)
        self.set_line_width(0.3)
        self.line(14, self.get_y(), 196, self.get_y())
        self.ln(3)

    def kv_row(self, key: str, value: str, val_color=None):
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*C_DIM)
        self.cell(60, 5, key, ln=False)
        self.set_text_color(*(val_color or C_WHITE))
        self.cell(0, 5, str(value), ln=True)

    def bar(self, label: str, count: int, total: int, color: tuple, w: float = 120):
        pct = count / max(total, 1)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_WHITE)
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

def build_report(es_client, hours: int = 24) -> bytes:
    now   = datetime.now(timezone.utc)
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
    pdf.cell(0, 10, "SYNDICATE4", align="C", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_DIM)
    pdf.cell(0, 6, "AI-Based Cyber Threat Detection - SOC Threat Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 5, f"Period: last {hours}h  ·  Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}",
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
    pdf.kv_row("Report period", f"{since[:10]} → {now.strftime('%Y-%m-%d')}")

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

    return bytes(pdf.output())
