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
