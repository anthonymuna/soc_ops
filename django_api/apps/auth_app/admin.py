from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import SOCUser

CARD_CHOICES = [
    ('stat_logs', 'Logs Scanned (Stat)'),
    ('stat_alerts', 'ML Alerts (Stat)'),
    ('stat_critical', 'Critical Alerts (Stat)'),
    ('stat_high', 'High Alerts (Stat)'),
    ('stat_session', 'Session Alerts (Stat)'),
    ('stat_model', 'Model Status (Stat)'),
    ('timeline', 'Timeline Chart'),
    ('heatmap', 'MITRE Heatmap'),
    ('alert_feed', 'Alert Feed'),
    ('alert_map', 'Geo Map'),
    ('model_status', 'Detailed Model Status'),
    ('class_breakdown', 'Attack Class Breakdown'),
]

class SOCUserForm(forms.ModelForm):
    visible_cards = forms.MultipleChoiceField(
        choices=CARD_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text="Select the dashboard cards this user is allowed to see."
    )

    class Meta:
        model = SOCUser
        fields = '__all__'

    def clean_visible_cards(self):
        return list(self.cleaned_data.get('visible_cards', []))

class SOCUserAdmin(UserAdmin):
    form = SOCUserForm
    fieldsets = UserAdmin.fieldsets + (
        ('Dashboard Configuration', {'fields': ('visible_cards',)}),
    )

admin.site.register(SOCUser, SOCUserAdmin)
