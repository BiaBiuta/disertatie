import json
import time
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import BlockedIP

_blocked_cache = {}
_cache_ttl = 2.0  # secunde


@database_sync_to_async
def is_ip_blocked(ip_address):
    """Verifică asincron în baza de date dacă IP-ul are o regulă activă și neexpirată."""
    if not ip_address:
        return False

    now_ts = time.time()
    if ip_address in _blocked_cache:
        cached_status, cached_time = _blocked_cache[ip_address]
        if now_ts - cached_time < _cache_ttl:
            return cached_status

    now = timezone.now()
    blocked = BlockedIP.objects.filter(
        ip_address=ip_address,
        is_active=True,
        expires_at__gt=now
    ).exists()

    _blocked_cache[ip_address] = (blocked, now_ts)
    return blocked


class AlertConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = "soc_stream"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        pass

    async def send_alert(self, event):
        payload = event.get("payload", {})
        src_ip = payload.get("src_ip")

        # 1. Verificare regulă firewall activă
        blocked = await is_ip_blocked(src_ip)

        # 2. Active Mitigation (IPS Tagging din zbor)
        if blocked:
            payload["severity"] = "CRITICAL"
            current_rule = payload.get("rule", "")
            if "[FIREWALL DROP]" not in current_rule:
                payload["rule"] = f"[FIREWALL DROP] {current_rule}"
            payload["final_risk"] = 1.0

        # 3. Transmitere către browser
        await self.send(text_data=json.dumps(payload))