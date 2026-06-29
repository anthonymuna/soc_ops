from django.db import models
from django.conf import settings


class HuntQuery(models.Model):
    """A saved ES query — analyst's reusable search."""
    name          = models.CharField(max_length=200)
    description   = models.TextField(blank=True)
    es_index      = models.CharField(max_length=100, default='syndicate4-ml-alerts')
    es_query      = models.JSONField()           # raw ES DSL body
    filters       = models.JSONField(default=dict)  # human-readable filter state for UI
    tags          = models.JSONField(default=list)  # e.g. ["lateral_movement", "BRU-001"]
    mitre_techniques = models.JSONField(default=list)
    created_by    = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at    = models.DateTimeField(auto_now_add=True)
    updated_at    = models.DateTimeField(auto_now=True)
    run_count     = models.IntegerField(default=0)
    last_run_at   = models.DateTimeField(null=True, blank=True)
    last_hit_count = models.IntegerField(default=0)
    is_active     = models.BooleanField(default=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.name} ({self.last_hit_count} hits)"


class HuntHypothesis(models.Model):
    """
    Pre-built hunting playbook. Seeded from existing Sigma rules.
    Analysts can also create custom hypotheses.
    """
    TACTIC_CHOICES = [
        ('initial_access', 'Initial Access'),
        ('discovery', 'Discovery'),
        ('credential_access', 'Credential Access'),
        ('lateral_movement', 'Lateral Movement'),
        ('command_and_control', 'Command & Control'),
        ('exfiltration', 'Exfiltration'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('impact', 'Impact'),
        ('persistence', 'Persistence'),
        ('defense_evasion', 'Defense Evasion'),
    ]

    hypothesis_id   = models.CharField(max_length=20, unique=True)  # e.g. HYP-001
    name            = models.CharField(max_length=200)
    description     = models.TextField()
    tactic          = models.CharField(max_length=50, choices=TACTIC_CHOICES)
    mitre_technique = models.CharField(max_length=20)               # e.g. T1046
    severity        = models.CharField(max_length=20)
    sigma_rule_ids  = models.JSONField(default=list)                # linked Sigma rules
    es_query        = models.JSONField()                            # pre-built ES query
    hunt_steps      = models.JSONField(default=list)               # list of step strings
    follow_up_queries = models.JSONField(default=list)             # suggested follow-ups
    is_builtin      = models.BooleanField(default=True)            # False = user-created
    run_count       = models.IntegerField(default=0)
    last_run_at     = models.DateTimeField(null=True, blank=True)
    last_hit_count  = models.IntegerField(default=0)
    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['tactic', 'hypothesis_id']

    def __str__(self):
        return f"{self.hypothesis_id}: {self.name}"


class HuntCampaign(models.Model):
    """A named investigation — groups queries, findings, notes."""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('paused', 'Paused'),
        ('closed_threat', 'Closed — Threat Confirmed'),
        ('closed_fp', 'Closed — False Positive'),
        ('escalated', 'Escalated to Incident'),
    ]

    name            = models.CharField(max_length=200)
    description     = models.TextField(blank=True)
    status          = models.CharField(
        max_length=30, choices=STATUS_CHOICES, default='active')
    lead_analyst    = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, related_name='led_campaigns')
    hypothesis      = models.ForeignKey(
        HuntHypothesis, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='campaigns')
    target_agents   = models.JSONField(default=list)   # agent names in scope
    target_ips      = models.JSONField(default=list)   # IPs under investigation
    mitre_techniques = models.JSONField(default=list)
    notes           = models.TextField(blank=True)     # analyst freeform notes
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)
    closed_at       = models.DateTimeField(null=True, blank=True)

    # Outcome metrics
    queries_run     = models.IntegerField(default=0)
    events_reviewed = models.IntegerField(default=0)
    findings_count  = models.IntegerField(default=0)
    false_positives = models.IntegerField(default=0)
    incident_id     = models.CharField(max_length=50, blank=True)  # e.g. INC-2024-047

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} [{self.status}]"


class HuntFinding(models.Model):
    """A confirmed event of interest found during a campaign."""
    VERDICT_CHOICES = [
        ('threat', 'Confirmed Threat'),
        ('suspicious', 'Suspicious — Needs Review'),
        ('false_positive', 'False Positive'),
        ('informational', 'Informational'),
    ]

    campaign        = models.ForeignKey(
        HuntCampaign, on_delete=models.CASCADE, related_name='findings')
    alert_id        = models.CharField(max_length=200, blank=True)  # ES doc ID if linked
    src_ip          = models.GenericIPAddressField(null=True, blank=True)
    agent_name      = models.CharField(max_length=100, blank=True)
    event_type      = models.CharField(max_length=100, blank=True)
    mitre_technique = models.CharField(max_length=20, blank=True)
    verdict         = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    title           = models.CharField(max_length=200)
    description     = models.TextField()
    raw_event       = models.JSONField(default=dict)   # snapshot of the ES document
    analyst_notes   = models.TextField(blank=True)
    created_by      = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class AgentBaseline(models.Model):
    """
    Behavioural baseline per Wazuh agent.
    Computed by background worker from 30-day ES history.
    """
    agent_name          = models.CharField(max_length=100, unique=True, db_index=True)
    
    # Volume baselines
    avg_hourly_events   = models.FloatField(default=0)
    avg_daily_events    = models.FloatField(default=0)
    std_hourly_events   = models.FloatField(default=0)   # standard deviation
    
    # Temporal baselines
    active_hours        = models.JSONField(default=list)  # list of ints 0-23 (EAT)
    active_days         = models.JSONField(default=list)  # list of ints 0-6 (Mon=0)
    
    # Network baselines
    top_src_ips         = models.JSONField(default=list)  # top 10 seen src IPs
    top_dst_ports       = models.JSONField(default=list)  # top 10 seen dst ports
    top_countries       = models.JSONField(default=list)  # top 5 src country codes
    top_attack_classes  = models.JSONField(default=list)  # typical ml_rf_class values
    
    # Computed at
    computed_at         = models.DateTimeField(auto_now=True)
    data_days           = models.IntegerField(default=0)  # how many days of data used

    class Meta:
        ordering = ['agent_name']

    def __str__(self):
        return f"Baseline: {self.agent_name} ({self.avg_daily_events:.0f} events/day)"


class BaselineDeviation(models.Model):
    """
    Auto-generated hunt lead when agent behaviour deviates from baseline.
    Shown in the Baselines tab as actionable hunt leads.
    """
    DEVIATION_TYPES = [
        ('volume_spike', 'Unusual Log Volume'),
        ('off_hours', 'Activity Outside Business Hours'),
        ('new_country', 'New Source Country'),
        ('new_port', 'New Destination Port'),
        ('new_ip', 'New Source IP'),
        ('attack_class_change', 'New Attack Class'),
        ('composite', 'Multiple Anomalies'),
    ]

    agent_name      = models.CharField(max_length=100, db_index=True)
    baseline        = models.ForeignKey(
        AgentBaseline, on_delete=models.CASCADE, related_name='deviations')
    deviation_type  = models.CharField(max_length=30, choices=DEVIATION_TYPES)
    severity        = models.CharField(max_length=20, default='medium')
    title           = models.CharField(max_length=200)
    description     = models.TextField()
    observed_value  = models.CharField(max_length=200)  # e.g. "847 events/hr"
    baseline_value  = models.CharField(max_length=200)  # e.g. "120 events/hr"
    deviation_factor = models.FloatField(default=1.0)   # e.g. 7.06x
    suggested_hypothesis = models.ForeignKey(
        HuntHypothesis, on_delete=models.SET_NULL,
        null=True, blank=True)
    detected_at     = models.DateTimeField(auto_now_add=True)
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True)

    class Meta:
        ordering = ['-detected_at']
