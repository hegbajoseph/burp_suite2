from django.db import models
import uuid


class ScanTarget(models.Model):
    STATUS_CHOICES = [
        ('pending',   'En attente'),
        ('running',   'En cours'),
        ('completed', 'Terminé'),
        ('failed',    'Échoué'),
    ]
    id           = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name         = models.CharField(max_length=255, blank=True)
    url          = models.URLField(max_length=500)
    status       = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at   = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_issues  = models.IntegerField(default=0)
    high_issues   = models.IntegerField(default=0)
    medium_issues = models.IntegerField(default=0)
    low_issues    = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.url})"


class ScanResult(models.Model):
    SEVERITY_CHOICES = [
        ('high',   'Haute'),
        ('medium', 'Moyenne'),
        ('low',    'Faible'),
        ('info',   'Info'),
    ]
    target      = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='results')
    url         = models.URLField(max_length=500)
    issue_type  = models.CharField(max_length=100)
    severity    = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    parameter   = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    evidence    = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.issue_type} - {self.severity}"


class ProxyRequest(models.Model):
    method           = models.CharField(max_length=10, default='GET')
    url              = models.URLField(max_length=500)
    headers          = models.TextField(blank=True)
    body             = models.TextField(blank=True)
    response_status  = models.IntegerField(null=True, blank=True)
    response_headers = models.TextField(blank=True)
    response_body    = models.TextField(blank=True)
    response_time    = models.FloatField(null=True, blank=True)
    intercepted      = models.BooleanField(default=False)
    timestamp        = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.method} {self.url}"


class IntruderPayload(models.Model):
    STATUS_CHOICES = [
        ('pending',   'En attente'),
        ('running',   'En cours'),
        ('completed', 'Terminé'),
    ]
    name        = models.CharField(max_length=255)
    attack_type = models.CharField(max_length=50, default='sniper')
    target_url  = models.URLField(max_length=500)
    body        = models.TextField(blank=True)
    payloads    = models.TextField(blank=True)  # JSON string
    results     = models.TextField(blank=True)  # JSON string
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class RepeaterRequest(models.Model):
    name             = models.CharField(max_length=255, default='Request')
    method           = models.CharField(max_length=10, default='GET')
    url              = models.URLField(max_length=500)
    headers          = models.TextField(blank=True)
    body             = models.TextField(blank=True)
    response_status  = models.IntegerField(null=True, blank=True)
    response_headers = models.TextField(blank=True)
    response_body    = models.TextField(blank=True)
    response_time    = models.FloatField(null=True, blank=True)
    created_at       = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.method} {self.url}"


class SpiderResult(models.Model):
    url          = models.URLField(max_length=500)
    status_code  = models.IntegerField(default=200)
    content_type = models.CharField(max_length=100, blank=True)
    title        = models.CharField(max_length=255, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url


class DecoderData(models.Model):
    input_data    = models.TextField()
    output_data   = models.TextField()
    encoding_type = models.CharField(max_length=50)
    operation     = models.CharField(max_length=20)
    created_at    = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.encoding_type} - {self.operation}"