from rest_framework import serializers
from .models import AlertFeedback, BlockedIP, PendingAction

class AlertFeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertFeedback
        fields = '__all__'

class PendingActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PendingAction
        fields = '__all__'

