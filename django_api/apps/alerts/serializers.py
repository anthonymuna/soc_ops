from rest_framework import serializers
from .models import AlertFeedback, BlockedIP

class AlertFeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertFeedback
        fields = '__all__'
