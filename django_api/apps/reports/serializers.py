from rest_framework import serializers
from .models import DailyReport

class DailyReportSerializer(serializers.ModelSerializer):
    generated_by_username = serializers.ReadOnlyField(source='generated_by.username')

    class Meta:
        model = DailyReport
        fields = [
            'id', 'title', 'generated_at', 'generated_by', 
            'generated_by_username', 'content', 'hours_covered', 'chart_data'
        ]
