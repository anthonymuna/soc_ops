from rest_framework import serializers
from .models import HuntQuery, HuntHypothesis, HuntCampaign, HuntFinding, AgentBaseline, BaselineDeviation


class HuntQuerySerializer(serializers.ModelSerializer):
    created_by_username = serializers.ReadOnlyField(source='created_by.username')

    class Meta:
        model = HuntQuery
        fields = '__all__'


class HuntHypothesisSerializer(serializers.ModelSerializer):
    class Meta:
        model = HuntHypothesis
        fields = '__all__'


class HuntFindingSerializer(serializers.ModelSerializer):
    created_by_username = serializers.ReadOnlyField(source='created_by.username')

    class Meta:
        model = HuntFinding
        fields = '__all__'


class HuntCampaignSerializer(serializers.ModelSerializer):
    lead_analyst_username = serializers.ReadOnlyField(source='lead_analyst.username')
    hypothesis_id = serializers.ReadOnlyField(source='hypothesis.hypothesis_id')
    hypothesis_name = serializers.ReadOnlyField(source='hypothesis.name')
    findings = HuntFindingSerializer(many=True, read_only=True)

    class Meta:
        model = HuntCampaign
        fields = '__all__'


class AgentBaselineSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentBaseline
        fields = '__all__'


class BaselineDeviationSerializer(serializers.ModelSerializer):
    suggested_hypothesis_id = serializers.ReadOnlyField(source='suggested_hypothesis.hypothesis_id')

    class Meta:
        model = BaselineDeviation
        fields = '__all__'
