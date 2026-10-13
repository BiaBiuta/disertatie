from django.db import models

class NetworkFlow(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.PositiveIntegerField()
    dst_port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10, default='TCP')
    flow_duration = models.FloatField(default=0.0)
    total_fwd_packets = models.PositiveIntegerField(default=0)
    total_bwd_packets = models.PositiveIntegerField(default=0)
    flow_bytes_per_sec = models.FloatField(default=0.0)
    flow_packets_per_sec = models.FloatField(default=0.0)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"

class SecurityAlert(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    flow = models.OneToOneField(NetworkFlow, on_delete=models.CASCADE, related_name='alert')
    rule_name = models.CharField(max_length=100, default='NONE')
    rule_score = models.FloatField(default=0.0)
    anomaly_score = models.FloatField(default=0.0)
    final_risk = models.FloatField(default=0.0)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='LOW')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.severity}] Risc: {self.final_risk:.2f} ({self.rule_name})"

from django.db import models
from django.utils import timezone


class BlockedIP(models.Model):
    """Regulă de blocare firewall generată manual sau automat la triajul alertelor."""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, default="Incident triage block")
    blocked_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-blocked_at']
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"

    def is_expired(self):
        if self.expires_at and timezone.now() > self.expires_at:
            return True
        return False

    def __str__(self):
        status = "ACTIVE" if self.is_active and not self.is_expired() else "EXPIRED"
        return f"{self.ip_address} [{status}] - {self.reason}"
class InspectedArtifact(models.Model):
    """Pastreaza rezultatele analizei statice asupra fisierelor asociate unui incident."""
    alert = models.ForeignKey(SecurityAlert, on_delete=models.CASCADE, related_name='artifacts', null=True, blank=True)
    file_name = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64)
    md5 = models.CharField(max_length=32, blank=True)
    entropy = models.FloatField()
    verdict = models.CharField(max_length=32)
    file_risk_score = models.FloatField()
    findings_json = models.TextField(default="[]")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.file_name} [{self.verdict}] - Entropie: {self.entropy}"
class SOARActionLog(models.Model):
    ACTION_CHOICES = [
        ('FIREWALL_BLOCK', 'Firewall Block (Containment)'),
        ('FIREWALL_UNBLOCK', 'Firewall Unblock (Release)'),
        ('AUTO_CONTAINMENT', 'Autonomous SOAR Isolation'),
        ('SANDBOX_ANALYSIS', 'Artifact Static Inspection'),
        ('IOC_BLACKLIST', 'IOC Hash Blacklisted'),
        ('RULE_EXPIRED', 'Firewall Rule Expired (TTL Cleanup)'),
    ]

    action_type = models.CharField(max_length=50, choices=ACTION_CHOICES)
    target = models.CharField(max_length=255)  # Ex: IP-ul atacatorului sau numele fisierului
    operator = models.CharField(max_length=100, default='SOC Analyst')
    details = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.created_at.strftime('%H:%M:%S')}] {self.action_type} - {self.target}"