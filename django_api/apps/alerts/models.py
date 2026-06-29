from django.db import models
from django.conf import settings

class AlertFeedback(models.Model):
    alert_id = models.CharField(max_length=200)
    label = models.CharField(max_length=50)
    comment = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    source = models.CharField(max_length=50, default='wazuh')

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField()
    blocked_at = models.DateTimeField(auto_now_add=True)
    blocked_by = models.CharField(max_length=100)
    reason = models.TextField()
    severity = models.CharField(max_length=20)
    is_active = models.BooleanField(default=True)
    unblocked_at = models.DateTimeField(null=True, blank=True)


class PendingAction(models.Model):
    triage_id = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    severity = models.CharField(max_length=50)
    incident_summary = models.TextField(blank=True)
    attack_pattern = models.CharField(max_length=200, blank=True)
    confidence = models.IntegerField(default=80)
    recommended_action = models.CharField(max_length=100, default='block')
    status = models.CharField(max_length=50, default='awaiting_approval')  # awaiting_approval, approved, dismissed, executed
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    agent_name = models.CharField(max_length=100, blank=True)
    abuseipdb_score = models.IntegerField(default=0)


class ThreatActorProfile(models.Model):
    """
    Persistent enriched profile for each unique source IP observed.
    Updated by background workers. Never enriched inline during a request.
    """
    THREAT_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('unknown', 'Unknown'),
    ]
    ATTACKER_TYPES = [
        ('apt', 'Advanced Persistent Threat'),
        ('targeted', 'Targeted Attack'),
        ('opportunistic', 'Opportunistic'),
        ('scanner', 'Mass Scanner'),
        ('botnet', 'Botnet Node'),
        ('unknown', 'Unknown'),
    ]

    # Identity
    ip_address          = models.GenericIPAddressField(unique=True, db_index=True)
    
    # MaxMind GeoLite2 fields
    city                = models.CharField(max_length=100, blank=True)
    country             = models.CharField(max_length=100, blank=True)
    country_iso         = models.CharField(max_length=5, blank=True)
    continent           = models.CharField(max_length=50, blank=True)
    latitude            = models.FloatField(null=True, blank=True)
    longitude           = models.FloatField(null=True, blank=True)
    asn                 = models.CharField(max_length=20, blank=True)   # e.g. AS12345
    asn_org             = models.CharField(max_length=200, blank=True)  # e.g. "Cloudflare Inc"
    isp                 = models.CharField(max_length=200, blank=True)
    connection_type     = models.CharField(max_length=50, blank=True)   # e.g. Cable/DSL/Corporate
    is_anonymous_proxy  = models.BooleanField(default=False)
    is_hosting_provider = models.BooleanField(default=False)
    is_tor_exit_node    = models.BooleanField(default=False)
    maxmind_enriched_at = models.DateTimeField(null=True, blank=True)

    # AbuseIPDB fields
    abuse_score         = models.IntegerField(default=0)   # 0-100
    abuse_total_reports = models.IntegerField(default=0)
    abuse_last_reported = models.DateTimeField(null=True, blank=True)
    abuse_categories    = models.JSONField(default=list)   # list of int category codes
    abuseipdb_enriched_at = models.DateTimeField(null=True, blank=True)

    # VirusTotal fields (optional — skip if no API key)
    vt_malicious_count  = models.IntegerField(default=0)
    vt_suspicious_count = models.IntegerField(default=0)
    vt_harmless_count   = models.IntegerField(default=0)
    vt_enriched_at      = models.DateTimeField(null=True, blank=True)

    # Internal NGAO SOC observed data
    first_seen          = models.DateTimeField(null=True, blank=True)
    last_seen           = models.DateTimeField(null=True, blank=True)
    total_events        = models.IntegerField(default=0)
    attack_classes      = models.JSONField(default=list)   # e.g. ["DoS", "R2L"]
    mitre_techniques    = models.JSONField(default=list)   # e.g. ["T1046", "T1110"]
    targeted_agents     = models.JSONField(default=list)   # agent names hit by this IP
    targeted_ports      = models.JSONField(default=list)   # ports targeted
    connectors_seen     = models.JSONField(default=list)   # wazuh/fortisiem/umbrella

    # Qwen AI analysis
    threat_level        = models.CharField(max_length=20, choices=THREAT_LEVELS, default='unknown')
    attacker_type       = models.CharField(max_length=20, choices=ATTACKER_TYPES, default='unknown')
    campaign_name       = models.CharField(max_length=200, blank=True)  # e.g. "East Africa Port Scan Wave"
    threat_summary      = models.TextField(blank=True)     # 2-3 sentence summary
    recommended_actions = models.JSONField(default=list)   # list of action strings
    analyst_notes       = models.TextField(blank=True)     # Qwen's detailed notes
    qwen_analyzed_at    = models.DateTimeField(null=True, blank=True)

    # Status tracking
    enrichment_status   = models.CharField(max_length=20, default='pending')
    # pending | enriching | complete | failed
    is_whitelisted      = models.BooleanField(default=False)
    is_blocked          = models.BooleanField(default=False)

    created_at          = models.DateTimeField(auto_now_add=True)
    updated_at          = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['threat_level']),
            models.Index(fields=['abuse_score']),
            models.Index(fields=['last_seen']),
            models.Index(fields=['country_iso']),
        ]

    def __str__(self):
        return f"{self.ip_address} [{self.threat_level}] — {self.country}"

    @property
    def composite_threat_score(self):
        """
        0-100 composite score combining all intel sources.
        Used for sorting and alerting thresholds.
        """
        score = 0
        score += min(self.abuse_score * 0.40, 40)           # AbuseIPDB: max 40 pts
        score += min(self.vt_malicious_count * 3, 25)        # VirusTotal: max 25 pts
        score += min(self.total_events * 0.5, 20)            # Internal frequency: max 20 pts
        score += 10 if self.is_tor_exit_node else 0          # Tor: +10 pts
        score += 5  if self.is_anonymous_proxy else 0        # Anon proxy: +5 pts
        return round(min(score, 100))


