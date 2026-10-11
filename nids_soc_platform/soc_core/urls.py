from django.urls import path
from .views import (
    dashboard_view,
    ingest_flow_api,
    alert_detail_api,
    block_ip_api,
    reports_view,
    export_incident_pdf_api,
trigger_evaluation_api,
get_blocked_ips_api,
unblock_ip_api
)

urlpatterns = [
    path('', dashboard_view, name='soc_dashboard'),
    path('reports/', reports_view, name='soc_reports'),
    path('api/ingest/', ingest_flow_api, name='api_ingest'),
    path('api/alert/<int:alert_id>/', alert_detail_api, name='api_alert_detail'),
    path('api/alert/<int:alert_id>/pdf/', export_incident_pdf_api, name='api_export_pdf'),
    path('api/block-ip/', block_ip_api, name='api_block_ip'),
path('api/recalculate-metrics/', trigger_evaluation_api, name='api_recalculate_metrics'),
# Rute Firewall / Active Response
    path('api/block-ip/', block_ip_api, name='api_block_ip'),
    path('api/blocked-ips/', get_blocked_ips_api, name='api_get_blocked_ips'),
    path('api/unblock-ip/', unblock_ip_api, name='api_unblock_ip'),
]