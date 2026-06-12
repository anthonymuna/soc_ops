from rest_framework import serializers
from .models import SOCUser

class SOCUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = SOCUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'visible_cards']
