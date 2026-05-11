def build_incident_report(alert: dict) -> bytes:
    """Build a detailed, single-incident threat intelligence report."""
    pdf = SocPDF(hours=0) # Hours not used for single report
    pdf.add_page()
    
    # ── Header ────────────────────────────────────────────────────────────────
    pdf.set_y(18)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*C_RED)
    pdf.cell(0, 10, "THREAT INTELLIGENCE REPORT", align="C", ln=True)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C_DIM)
    pdf.cell(0, 6, f"Incident ID: {str(alert.get('id', 'UNK'))[:12]} | Confirmed Threat", align="C", ln=True)
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
            "• Implement Rate Limiting: Apply strict bandwidth throttling on source IP.",
            "• Firewall Drop: Immediate drop of all traffic from identified malicious source.",
            "• Traffic Analysis: Monitor for secondary amplification patterns.",
        ],
        "probe": [
            "• Network Isolation: Place the target subnet behind enhanced ACLs.",
            "• Scan Verification: Run a fresh internal scan to check for exposed vulnerabilities.",
            "• Log Review: Correlate with firewall logs to find other probe attempts.",
        ],
        "r2l": [
            "• Credentials Reset: Force password rotation for any accounts accessed by the source.",
            "• Session Termination: Terminate all active sessions involving the target host.",
            "• Multi-Factor Authentication: Audit and enforce MFA on all external endpoints.",
        ],
        "u2r": [
            "• System Isolation: Immediately disconnect the compromised host from the network.",
            "• Forensic Imaging: Take a full snapshot of the host memory and disk for analysis.",
            "• Privilege Audit: Review all sudo/admin privilege escalations in the last 24 hours.",
        ],
        "anomaly": [
            "• Traffic Mirroring: Set up a span port to capture raw packets for this flow.",
            "• Host Baseline: Compare current host behavior with established normal baseline.",
            "• Signature Update: Create a temporary Snort/Suricata rule to block this pattern.",
        ]
    }
    
    rec_list = actions.get(alert.get("ml_rf_class", "anomaly"), actions["anomaly"])
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C_RED)
    pdf.cell(0, 7, "MANDATORY ACTIONS:", ln=True)
    pdf.ln(1)
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_TEXT)
    for action in rec_list:
        pdf.multi_cell(180, 6, action)
    
    pdf.ln(15)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(*C_DIM)
    pdf.cell(0, 5, "End of Intel Report. Generated by Syndicate 4 Autonomous SOC Platform.", align="C")

    return pdf.output(dest='S')
