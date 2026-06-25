from django.contrib.auth.models import AbstractUser
from django.db import models

class SOCUser(AbstractUser):
    visible_cards = models.JSONField(default=list, blank=True)
