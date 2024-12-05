from django.db import models
from django.contrib.auth.models import User

class TrackedRequest(models.Model):
    unique_id = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=45)
    user_agent = models.TextField(null=True, blank=True)
    referrer = models.TextField(null=True, blank=True)
    geolocation = models.TextField(null=True, blank=True)
    headers = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    group_name = models.CharField(max_length=255, null=True, blank=True)
    hidden = models.BooleanField(default=False)
