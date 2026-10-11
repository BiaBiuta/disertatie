import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import BlockedIP


@database_sync_to_async
def is_ip_blocked(ip_address):
    """Verifică asincron în baza de date dacă IP-ul are o regulă activă și neexpirată."""
    if not ip_address:
        return False
    return BlockedIP.objects.filter(
        ip_address=ip_address,
        is_active=True,
        expires_at__gt=timezone.now()
    ).exists()


class AlertConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = "soc_stream"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def send_alert(self, event):
        payload = event.get("payload", {})
        src_ip = payload.get("src_ip")

        # 1. Verificăm dacă adresa sursă este blocată în firewall
        blocked = await is_ip_blocked(src_ip)

        # 2. Dacă IP-ul este pe lista neagră, modificăm alerta din zbor (Active Mitigation / IPS)
        if blocked:
            payload["severity"] = "CRITICAL"
            current_rule = payload.get("rule", "")
            if "[FIREWALL DROP]" not in current_rule:
                payload["rule"] = f"[FIREWALL DROP] {current_rule}"
            payload["final_risk"] = 1.0  # Risc maxim

        # 3. Transmitem alerta actualizată către browser
        await self.send(text_data=json.dumps(payload))