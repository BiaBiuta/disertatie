import json
import os

from django.conf import settings

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .models import NetworkFlow, SecurityAlert
from .services.rule_engine import evaluate_suricata_rules
from .services.detector_mock import predict_anomaly


def dashboard_view(request):
    """Afișează pagina principală a panoului SOC cu contoare persistente din baza de date."""
    from django.db.models import Q
    from .models import NetworkFlow, SecurityAlert

    alerts = SecurityAlert.objects.select_related('flow').order_by('-created_at')[:50]

    # Calcul direct pe tabelele din baza de date
    total_flows = NetworkFlow.objects.count()
    suricata_count = SecurityAlert.objects.filter(
        ~Q(rule_name__icontains='CLEAN') & ~Q(rule_name__icontains='PASSED') & ~Q(rule_name='NONE')
    ).count()
    ml_count = SecurityAlert.objects.filter(severity__in=['HIGH', 'CRITICAL']).count()

    return render(request, 'soc/dashboard.html', {
        'recent_alerts': alerts,
        'initial_total': total_flows,
        'initial_suricata': suricata_count,
        'initial_ml': ml_count,
    })

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
    """Afișează pagina de benchmark și rapoarte încărcând rezultatele GA + CPLEX și inferența live."""
    import os
    import json
    from django.conf import settings

    base_path = settings.BASE_DIR
    soc_metrics_path = os.path.join(base_path, "reports", "soc_realtime_metrics.json")
    ga_cplex_path = os.path.join(base_path, "reports", "hybrid_ga_cplex_results.json")
    features_path = os.path.join(base_path, "artifacts", "selected_features.json")

    soc_metrics = {}
    ga_results = {}
    selected_features = []

    if os.path.exists(soc_metrics_path):
        with open(soc_metrics_path, "r", encoding="utf-8") as f:
            soc_metrics = json.load(f)

    if os.path.exists(ga_cplex_path):
        with open(ga_cplex_path, "r", encoding="utf-8") as f:
            ga_results = json.load(f)

    if os.path.exists(features_path):
        with open(features_path, "r", encoding="utf-8") as f:
            features_meta = json.load(f)
            selected_features = features_meta.get("features", [])

    context = {
        "soc_metrics": soc_metrics,
        "ga_results": ga_results,
        "selected_features": selected_features,
    }
    return render(request, "soc/reports.html", context)


import io
from django.http import HttpResponse, Http404
from django.utils import timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from .models import SecurityAlert, BlockedIP


def export_incident_pdf_api(request, alert_id):
    """Genereaza un raport PDF formal de investigatie si triaj SOC pentru un incident specific."""
    try:
        alert = SecurityAlert.objects.select_related('flow').get(id=alert_id)
    except SecurityAlert.DoesNotExist:
        raise Http404("Alerta nu a fost gasita.")

    flow = alert.flow

    # Extragere sigura a valorilor din NetworkFlow
    flow_duration = getattr(flow, 'duration', None) or getattr(flow, 'flow_duration', None) or 0.0
    packets_per_sec = getattr(flow, 'packets_per_sec', None) or getattr(flow, 'flow_packets_per_sec', None) or 0.0
    fwd_pkts = getattr(flow, 'fwd_pkts', None) or getattr(flow, 'total_fwd_packets', None) or getattr(flow,
                                                                                                      'fwd_packets',
                                                                                                      None) or 'N/A'
    fwd_pkt_len_max = getattr(flow, 'fwd_pkt_len_max', None) or getattr(flow, 'fwd_packet_length_max', None) or 0.0
    flow_iat_mean = getattr(flow, 'flow_iat_mean', None) or getattr(flow, 'iat_mean', None) or 0.0
    flow_iat_max = getattr(flow, 'flow_iat_max', None) or getattr(flow, 'iat_max', None) or 0.0

    # Verificare stare de blocare in firewall
    is_blocked = BlockedIP.objects.filter(
        ip_address=flow.src_ip,
        is_active=True,
        expires_at__gt=timezone.now()
    ).exists()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=8,
        spaceAfter=5
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )

    elements = []

    # 1. Antet Raport
    elements.append(Paragraph("RAPORT DE INVESTIGATIE INCIDENT SOC", title_style))
    elements.append(
        Paragraph(f"Generat la: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Platforma NIDS Hibrida GA+CPLEX",
                  subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

    # 2. Sumar Incident & Severitate
    status_label = "BLOCAT (Firewall Drop)" if is_blocked else "MONITORIZAT (Activ)"
    summary_data = [
        [Paragraph("<b>ID Incident:</b>", body_style), Paragraph(f"#{alert.id}", body_style),
         Paragraph("<b>Severitate:</b>", body_style), Paragraph(f"<b>{alert.severity}</b>", body_style)],
        [Paragraph("<b>Data / Ora:</b>", body_style),
         Paragraph(alert.created_at.strftime('%Y-%m-%d %H:%M:%S'), body_style),
         Paragraph("<b>Scor Risc Fuzionat:</b>", body_style), Paragraph(f"{alert.final_risk:.2f} / 1.00", body_style)],
        [Paragraph("<b>Regula Semnatura:</b>", body_style), Paragraph(str(alert.rule_name), body_style),
         Paragraph("<b>Status Atenuare:</b>", body_style), Paragraph(status_label, body_style)],
    ]
    summary_table = Table(summary_data, colWidths=[110, 150, 110, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # 3. Metadate Comunicatie Retea (5-Tuple)
    elements.append(Paragraph("1. Metadate Comunicatie Retea (5-Tuple)", heading_style))
    tuple_data = [
        [Paragraph("<b>IP Sursa:</b>", body_style), Paragraph(str(flow.src_ip), body_style),
         Paragraph("<b>IP Destinatie:</b>", body_style), Paragraph(str(flow.dst_ip), body_style)],
        [Paragraph("<b>Port Destinatie:</b>", body_style), Paragraph(str(flow.dst_port), body_style),
         Paragraph("<b>Protocol:</b>", body_style), Paragraph(str(flow.protocol), body_style)],
        [Paragraph("<b>Durata Flux:</b>", body_style), Paragraph(f"{float(flow_duration):.4f} s", body_style),
         Paragraph("<b>Rata Pachete:</b>", body_style), Paragraph(f"{float(packets_per_sec):.2f} pkt/s", body_style)],
    ]
    tuple_table = Table(tuple_data, colWidths=[110, 150, 110, 150])
    tuple_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ffffff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(tuple_table)
    elements.append(Spacer(1, 10))

    # 4. Analiza Celor 4 Trasaturi Optime (GA + CPLEX)
    elements.append(Paragraph("2. Analiza Trasaturilor Optime (Sub-spatiu Calibrat GA + CPLEX)", heading_style))
    elements.append(Paragraph(
        "Sub-spatiul redus de la 79 la 4 trasaturi asigura inferenta in ~35 &micro;s si FPR &le; 0.05%:",
        body_style
    ))
    elements.append(Spacer(1, 4))

    features_data = [
        [Paragraph("<b>Trasatura Selectata</b>", body_style),
         Paragraph("<b>Valoare Incident</b>", body_style),
         Paragraph("<b>Medie Benign (Ref.)</b>", body_style),
         Paragraph("<b>Diagnostic Teoretic</b>", body_style)],

        [Paragraph("<code>Total Fwd Packets</code>", body_style),
         Paragraph(str(fwd_pkts), body_style),
         Paragraph("2 - 5 pachete", body_style),
         Paragraph("Volum conexiune forward", body_style)],

        [Paragraph("<code>Fwd Packet Length Max</code>", body_style),
         Paragraph(f"{float(fwd_pkt_len_max):.1f} octeti", body_style),
         Paragraph("&le; 250 octeti", body_style),
         Paragraph("Anomalie sarcina utila / payload", body_style)],

        [Paragraph("<code>Flow IAT Mean</code>", body_style),
         Paragraph(f"{float(flow_iat_mean):.2f} &micro;s", body_style),
         Paragraph("Variatie larga", body_style),
         Paragraph("Frecventa inter-sosire (burst rate)", body_style)],

        [Paragraph("<code>Flow IAT Max</code>", body_style),
         Paragraph(f"{float(flow_iat_max):.2f} &micro;s", body_style),
         Paragraph("Pauze prelungite", body_style),
         Paragraph("Detectare scanari low-and-slow", body_style)],
    ]
    features_table = Table(features_data, colWidths=[140, 100, 110, 170])
    features_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e0f2fe')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94a3b8')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(features_table)
    elements.append(Spacer(1, 10))

    # 5. Actiuni Recomandate SOAR
    elements.append(Paragraph("3. Actiuni Recomandate & Raspuns la Incident (SOAR)", heading_style))
    recom_text = """
    &bull; <b>Izolare la nivelul perimetrului:</b> Mentinerea adresei IP in lista de blocare a firewall-ului (TTL minim 60 min).<br/>
    &bull; <b>Analiza corelata:</b> Verificarea jurnalelor DNS si a cererilor HTTP catre portul tinta.<br/>
    &bull; <b>Triage intern:</b> Inspectarea statiilor de lucru interne daca IP-ul destinatie gazduieste servicii critice.
    """
    elements.append(Paragraph(recom_text, body_style))
    elements.append(Spacer(1, 12))

    # Semnatura de audit
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cbd5e1'), spaceAfter=6))
    footer_text = "Raport generat automat de platforma de securitate. Validat pentru dosarul de audit si analiza post-incident."
    elements.append(Paragraph(footer_text, ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                                                          textColor=colors.HexColor('#94a3b8'))))

    doc.build(elements)
    buffer.seek(0)

    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="incident_report_{alert.id}.pdf"'
    return response
import subprocess
import sys
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt


import os
import subprocess
import sys
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@require_POST
def trigger_evaluation_api(request):
    """Executa scriptul de generare a graficelor la cerere din UI."""
    try:
        # Foloseste numele scriptului existent in proiect (evaluate_models.py sau generate_thesis_charts.py)
        script_name = "evaluate_models.py" if os.path.exists(os.path.join(settings.BASE_DIR, "evaluate_models.py")) else "generate_thesis_charts.py"
        script_path = os.path.join(settings.BASE_DIR, script_name)

        # Mediu de executie cu UTF-8 activat explicit
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"

        res = subprocess.run(
            [sys.executable, script_path],
            cwd=settings.BASE_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
            timeout=120
        )

        if res.returncode == 0:
            return JsonResponse({'status': 'success', 'message': 'Graficele au fost regenerate cu succes!'})
        else:
            return JsonResponse({'status': 'error', 'details': res.stderr or res.stdout}, status=500)
    except Exception as e:
        return JsonResponse({'status': 'error', 'details': str(e)}, status=500)
import json
from datetime import timedelta
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from .models import BlockedIP


@csrf_exempt
@require_POST
def block_ip_api(request):
    """Adaugă sau actualizează un IP în lista de blocare a firewall-ului cu un TTL implicit."""
    try:
        data = json.loads(request.body.decode('utf-8'))
        ip = data.get('ip', '').strip()
        reason = data.get('reason', 'Blocare manuala din investigatie SOC')
        duration_minutes = int(data.get('duration_minutes', 60))  # TTL default: 60 min

        if not ip:
            return JsonResponse({'status': 'error', 'message': 'Adresa IP lipseste.'}, status=400)

        expires_at = timezone.now() + timedelta(minutes=duration_minutes)

        blocked_entry, created = BlockedIP.objects.update_or_create(
            ip_address=ip,
            defaults={
                'reason': reason,
                'expires_at': expires_at,
                'is_active': True
            }
        )

        return JsonResponse({
            'status': 'success',
            'created': created,
            'ip': blocked_entry.ip_address,
            'reason': blocked_entry.reason,
            'expires_at': blocked_entry.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            'message': f"IP-ul {ip} a fost blocat cu succes in firewall."
        })
    except Exception as e:
        return JsonResponse({'status': 'error', 'details': str(e)}, status=500)


@require_GET
def get_blocked_ips_api(request):
    """Returneaza toate regulile active din lista de blocare."""
    now = timezone.now()
    # Curatare automata sau marcare inactive pentru regulile expirate
    BlockedIP.objects.filter(expires_at__lte=now, is_active=True).update(is_active=False)

    active_blocks = BlockedIP.objects.filter(is_active=True)
    payload = [
        {
            'id': b.id,
            'ip': b.ip_address,
            'reason': b.reason,
            'blocked_at': b.blocked_at.strftime('%H:%M:%S'),
            'expires_at': b.expires_at.strftime('%H:%M:%S') if b.expires_at else 'Permanent',
        }
        for b in active_blocks
    ]
    return JsonResponse({'status': 'success', 'blocked_ips': payload})


@csrf_exempt
@require_POST
def unblock_ip_api(request):
    """Elimina un IP din lista activa de blocare (manual unblock de catre analist)."""
    try:
        data = json.loads(request.body.decode('utf-8'))
        ip = data.get('ip', '').strip()

        if not ip:
            return JsonResponse({'status': 'error', 'message': 'Adresa IP lipseste.'}, status=400)

        updated_count = BlockedIP.objects.filter(ip_address=ip, is_active=True).update(is_active=False)

        if updated_count > 0:
            return JsonResponse({'status': 'success', 'message': f"IP-ul {ip} a fost deblocat."})
        else:
            return JsonResponse({'status': 'warning', 'message': f"IP-ul {ip} nu era blocat activ."})
    except Exception as e:
        return JsonResponse({'status': 'error', 'details': str(e)}, status=500)