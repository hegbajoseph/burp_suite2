from django.db import models
import uuid


# ─── Scanner ──────────────────────────────────────────────────────────────────

class ScanTarget(models.Model):
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('running', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=500)
    name = models.CharField(max_length=255, blank=True, default='')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_issues = models.IntegerField(default=0)
    high_issues = models.IntegerField(default=0)
    medium_issues = models.IntegerField(default=0)
    low_issues = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name or self.url} - {self.status}"


class ScanResult(models.Model):
    SEVERITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    ISSUE_TYPES = [
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('sqli', 'SQL Injection'),
        ('csrf', 'CSRF'),
        ('open_redirect', 'Open Redirect'),
        ('missing_header', 'Missing Security Header'),
        ('info_disclosure', 'Information Disclosure'),
        ('ssl', 'SSL/TLS Issue'),
        ('clickjacking', 'Clickjacking'),
    ]

    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='results')
    issue_type = models.CharField(max_length=50, choices=ISSUE_TYPES, default='info')
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info')
    url = models.URLField(max_length=500, blank=True)
    parameter = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    request_data = models.TextField(blank=True)
    response_data = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-severity', 'issue_type']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.issue_type} - {self.url}"


class ScanIssue(models.Model):
    SEVERITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    ISSUE_TYPES = [
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('sqli', 'SQL Injection'),
        ('csrf', 'CSRF'),
        ('open_redirect', 'Open Redirect'),
        ('missing_header', 'Missing Security Header'),
        ('info_disclosure', 'Information Disclosure'),
        ('ssl', 'SSL/TLS Issue'),
        ('clickjacking', 'Clickjacking'),
    ]

    scan = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='issues')
    issue_type = models.CharField(max_length=50, choices=ISSUE_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=255)
    description = models.TextField()
    url = models.URLField(max_length=500)
    parameter = models.CharField(max_length=255, blank=True)
    payload = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-severity', 'issue_type']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title} - {self.url}"


# ─── Proxy ────────────────────────────────────────────────────────────────────

class ProxyRequest(models.Model):
    METHOD_CHOICES = [
        ('GET', 'GET'), ('POST', 'POST'), ('PUT', 'PUT'),
        ('DELETE', 'DELETE'), ('PATCH', 'PATCH'),
        ('HEAD', 'HEAD'), ('OPTIONS', 'OPTIONS'),
    ]

    method = models.CharField(max_length=10, choices=METHOD_CHOICES, default='GET')
    url = models.URLField(max_length=1000)
    host = models.CharField(max_length=255, blank=True, default='')
    path = models.CharField(max_length=1000, blank=True, default='/')
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.TextField(blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True)
    response_length = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True)
    intercepted = models.BooleanField(default=False)
    modified = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.method} {self.url} [{self.response_status}]"


# ─── Intruder ─────────────────────────────────────────────────────────────────

class IntruderPayload(models.Model):
    ATTACK_TYPES = [
        ('sniper', 'Sniper'),
        ('battering_ram', 'Battering Ram'),
        ('pitchfork', 'Pitchfork'),
        ('cluster_bomb', 'Cluster Bomb'),
    ]
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('running', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ]

    name = models.CharField(max_length=255, blank=True, default='')
    attack_type = models.CharField(max_length=20, choices=ATTACK_TYPES, default='sniper')
    target_url = models.URLField(max_length=1000)
    request_template = models.TextField(blank=True)
    payloads = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    results = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name or self.target_url} [{self.attack_type}]"


# ─── Repeater ─────────────────────────────────────────────────────────────────

class RepeaterRequest(models.Model):
    name = models.CharField(max_length=255, blank=True, default='')
    method = models.CharField(max_length=10, default='GET')
    url = models.URLField(max_length=1000)
    headers = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True)
    response_time = models.FloatField(null=True, blank=True)
    history = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.name or self.url} [{self.method}]"


# ─── Spider ───────────────────────────────────────────────────────────────────

class SpiderResult(models.Model):
    url = models.URLField(max_length=1000)
    status_code = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=100, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    parent_url = models.URLField(max_length=1000, blank=True)
    title = models.CharField(max_length=500, blank=True)
    links_found = models.IntegerField(default=0)
    forms_found = models.IntegerField(default=0)
    depth = models.IntegerField(default=0)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']

    def __str__(self):
        return f"{self.url} [{self.status_code}]"


# ─── Decoder ──────────────────────────────────────────────────────────────────

class DecoderData(models.Model):
    ENCODING_TYPES = [
        ('base64', 'Base64'), ('url', 'URL'), ('html', 'HTML'),
        ('hex', 'Hex'), ('binary', 'Binary'),
        ('md5', 'MD5'), ('sha1', 'SHA1'), ('sha256', 'SHA256'),
    ]
    OPERATIONS = [
        ('encode', 'Encode'), ('decode', 'Decode'), ('hash', 'Hash'),
    ]

    input_data = models.TextField()
    output_data = models.TextField(blank=True)
    encoding_type = models.CharField(max_length=20, choices=ENCODING_TYPES)
    operation = models.CharField(max_length=10, choices=OPERATIONS)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.operation} [{self.encoding_type}] - {self.created_at}"