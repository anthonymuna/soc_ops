from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import SOCUser

class SOCUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ('Dashboard Configuration', {'fields': ('visible_cards',)}),
    )

admin.site.register(SOCUser, SOCUserAdmin)
