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
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} ({self.reason})"
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