from django.db import models
from django.conf import settings

class ReportJob(models.Model):
    requested_at = models.DateTimeField(auto_now_add=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    hours = models.IntegerField(default=24)
    status = models.CharField(max_length=20, default='pending')
    completed_at = models.DateTimeField(null=True)
