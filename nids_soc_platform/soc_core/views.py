import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .models import NetworkFlow, SecurityAlert
from .services.rule_engine import evaluate_suricata_rules
from .services.detector_mock import predict_anomaly

def dashboard_view(request):
    """Afișează pagina principală a panoului SOC cu ultimele alerte."""
    alerts = SecurityAlert.objects.order_by('-created_at')[:20]
    return render(request, 'soc/dashboard.html', {'recent_alerts': alerts})

@csrf_exempt
def ingest_flow_api(request):
    """Endpoint REST unde simulatorul trimite fluxuri brute de rețea."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        data = json.loads(request.body)
    except Exception as e:
        return JsonResponse({'error': f'Invalid JSON: {e}'}, status=400)

    # 1. Salvare flux brut în baza de date
    flow = NetworkFlow.objects.create(
        src_ip=data.get('src_ip', '127.0.0.1'),
        dst_ip=data.get('dst_ip', '127.0.0.1'),
        src_port=int(data.get('src_port', 0)),
        dst_port=int(data.get('dst_port', 0)),
        protocol=data.get('protocol', 'TCP'),
        flow_duration=float(data.get('flow_duration', 0.0)),
        total_fwd_packets=int(data.get('total_fwd_packets', 0)),
        total_bwd_packets=int(data.get('total_bwd_packets', 0)),
        flow_bytes_per_sec=float(data.get('flow_bytes_per_sec', 0.0)),
        flow_packets_per_sec=float(data.get('flow_packets_per_sec', 0.0))
    )

    # 2. Pipeline Hibrid: Reguli deterministe Suricata-like + PyOD
    rule_result = evaluate_suricata_rules(data)

    if not rule_result.get("needs_ml", True):
        # Declanșat de reguli deterministe (ex: scanare porturi, brute-force)
        rule_name = rule_result.get("signature", "MATCHED_RULE")
        rule_score = rule_result.get("score", 0.8)
        ml_score = 0.0
        final_risk = rule_score
        severity = 'CRITICAL' if rule_score >= 0.85 else 'HIGH'
    else:
        # A trecut de reguli -> Evaluare cu modelul de anomalii (Isolation Forest)
        ml_score, is_over_threshold = predict_anomaly(data)
        rule_name = "CLEAN (SURICATA_PASSED)"
        rule_score = 0.0
        final_risk = round(ml_score, 2)
        severity = 'HIGH' if is_over_threshold else 'LOW'

    # 3. Creare înregistrare de alertă
    alert = SecurityAlert.objects.create(
        flow=flow,
        rule_name=rule_name,
        rule_score=rule_score,
        anomaly_score=ml_score,
        final_risk=final_risk,
        severity=severity
    )

    # 4. Transmitere eveniment live pe WebSocket
    channel_layer = get_channel_layer()
    payload = {
        'id': alert.id,
        'timestamp': alert.created_at.strftime("%H:%M:%S"),
        'src_ip': flow.src_ip,
        'dst_ip': flow.dst_ip,
        'dst_port': flow.dst_port,
        'protocol': flow.protocol,
        'rule': alert.rule_name,
        'ml_score': alert.anomaly_score,
        'final_risk': alert.final_risk,
        'severity': alert.severity
    }
    async_to_sync(channel_layer.group_send)(
        "soc_stream",
        {"type": "send_alert", "payload": payload}
    )

    return JsonResponse({
        'status': 'processed',
        'alert_id': alert.id,
        'final_risk': final_risk,
        'severity': severity
    })


from django.views.decorators.http import require_http_methods
from .models import BlockedIP


@require_http_methods(["GET"])
def alert_detail_api(request, alert_id):
    """Returnează analiza aprofundată a unui flux pentru fereastra modală de investigare."""
    try:
        alert = SecurityAlert.objects.select_related('flow').get(id=alert_id)
        flow = alert.flow
        return JsonResponse({
            'id': alert.id,
            'timestamp': alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'severity': alert.severity,
            'rule_name': alert.rule_name,
            'rule_score': alert.rule_score,
            'anomaly_score': alert.anomaly_score,
            'final_risk': alert.final_risk,
            'flow_details': {
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'src_port': flow.src_port,
                'dst_port': flow.dst_port,
                'protocol': flow.protocol,
                'duration': flow.flow_duration,
                'fwd_pkts': flow.total_fwd_packets,
                'bwd_pkts': flow.total_bwd_packets,
                'bytes_per_sec': flow.flow_bytes_per_sec,
                'packets_per_sec': flow.flow_packets_per_sec
            }
        })
    except SecurityAlert.DoesNotExist:
        return JsonResponse({'error': 'Alert not found'}, status=404)


@csrf_exempt
@require_http_methods(["POST"])
def block_ip_api(request):
    """Adaugă o adresă IP în lista de blocare SOC."""
    try:
        data = json.loads(request.body)
        ip = data.get('ip')
        reason = data.get('reason', 'Manual triage from SOC Dashboard')
        if not ip:
            return JsonResponse({'error': 'IP required'}, status=400)

        obj, created = BlockedIP.objects.get_or_create(ip_address=ip, defaults={'reason': reason})
        return JsonResponse({'status': 'success', 'ip': ip, 'created': created})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
def reports_view(request):
    """Afișează pagina de performanță a modelelor și rapoartele de acuratețe."""
    return render(request, 'soc/reports.html')
import io
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

@require_http_methods(["GET"])
def export_incident_pdf_api(request, alert_id):
    """Generează și descarcă un raport tehnic de securitate (SOC Incident Report) în format PDF."""
    try:
        alert = SecurityAlert.objects.select_related('flow').get(id=alert_id)
        flow = alert.flow
    except SecurityAlert.DoesNotExist:
        return JsonResponse({'error': 'Alert not found'}, status=404)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    elements = []
    styles = getSampleStyleSheet()

    # Stiluri personalizate
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=1, # Centrat
        spaceAfter=15
    )
    section_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=8
    )
    normal_style = styles['Normal']

    # 1. Antet Raport
    elements.append(Paragraph(f"SOC Incident Technical Report — #{alert.id}", title_style))
    elements.append(Paragraph(f"<b>Data Raportării:</b> {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style))
    elements.append(Paragraph(f"<b>Clasificare Triage:</b> Raport generat automat prin NIDS SOC Platform", normal_style))
    elements.append(Spacer(1, 15))

    # 2. Sumar Decizie Securitate
    elements.append(Paragraph("1. Evaluare și Decizie de Securitate", section_style))
    decision_data = [
        ["Câmp", "Valoare"],
        ["Severitate Incident", alert.severity],
        ["Scor Risc Final (Fuzionat)", f"{alert.final_risk:.2f}"],
        ["Semnătură / Regulă Declansată", alert.rule_name],
        ["Pondere Regulă Deterministică", f"{alert.rule_score:.2f}"],
        ["Scor Ansamblu ML (PyOD)", f"{alert.anomaly_score:.3f}"],
    ]
    t_decision = Table(decision_data, colWidths=[200, 340])
    t_decision.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
    ]))
    elements.append(t_decision)
    elements.append(Spacer(1, 15))

    # 3. Metadate Flux Rețea (CIC-IDS2017)
    elements.append(Paragraph("2. Parametri Tehnici Flux de Rețea", section_style))
    flow_data = [
        ["Parametru Rețea", "Valoare Înregistrată"],
        ["IP Sursă -> IP Destinație", f"{flow.src_ip} -> {flow.dst_ip}"],
        ["Port Destinație / Protocol", f"{flow.dst_port} / {flow.protocol}"],
        ["Durată Flux", f"{flow.flow_duration} s"],
        ["Total Pachete (Forward / Backward)", f"{flow.total_fwd_packets} fwd / {flow.total_bwd_packets} bwd"],
        ["Rată Octeți / Secundă (Flow Bytes/s)", f"{flow.flow_bytes_per_sec:,.2f}"],
        ["Rată Pachete / Secundă (Flow Packets/s)", f"{flow.flow_packets_per_sec:,.2f}"],
    ]
    t_flow = Table(flow_data, colWidths=[200, 340])
    t_flow.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
    ]))
    elements.append(t_flow)
    elements.append(Spacer(1, 15))

    # 4. Concluzie Triage SOC
    elements.append(Paragraph("3. Concluzii și Recomandare Analist", section_style))
    recom_text = (
        "Fluxul analizat a fost evaluat de pipeline-ul hibrid. Dacă severitatea este CRITICAL sau HIGH, "
        "se recomandă aplicarea unei reguli de firewall pentru blocarea IP-ului sursă sau carantinarea "
        "nodului afectat din rețeaua internă."
    )
    elements.append(Paragraph(recom_text, normal_style))

    doc.build(elements)
    buffer.seek(0)

    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="incident_report_alert_{alert.id}.pdf"'
    return response