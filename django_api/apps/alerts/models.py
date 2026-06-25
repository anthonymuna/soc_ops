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

