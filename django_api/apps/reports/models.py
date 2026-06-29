from django.db import models
from django.conf import settings

class ReportJob(models.Model):
    requested_at = models.DateTimeField(auto_now_add=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    hours = models.IntegerField(default=24)
    status = models.CharField(max_length=20, default='pending')
    completed_at = models.DateTimeField(null=True)


class DailyReport(models.Model):
    title = models.CharField(max_length=200)
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    content = models.TextField()  # Markdown generated report content
    hours_covered = models.IntegerField(default=24)
    chart_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-generated_at']

    def __str__(self):
        return f"{self.title} - {self.generated_at.strftime('%Y-%m-%d')}"
