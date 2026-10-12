import io
import json
import os
import subprocess
import sys
from datetime import timedelta

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.db.models import Q
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import BlockedIP, InspectedArtifact, NetworkFlow, SecurityAlert, SOARActionLog
from .services.detector_mock import predict_anomaly
from .services.pe_analyzer import analyze_pe_bytes
from .services.rule_engine import evaluate_suricata_rules


# =====================================================================
# 1. VIEW-URI PAGINI PRINCIPALE (TEMPLATES)
# =====================================================================

def dashboard_view(request):
    """Afișează pagina principală a panoului SOC cu contoare persistente din baza de date."""
    alerts = SecurityAlert.objects.select_related('flow').order_by('-created_at')[:50]
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


def sandbox_view(request):
    """Pagina dedicată pentru analiză statică de binare (XDR Sandbox)."""
    return render(request, 'soc/sandbox.html')


def reports_view(request):
    """Afișează pagina de benchmark și rapoarte încărcând rezultatele GA + CPLEX."""
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

    return render(request, "soc/reports.html", {
        "soc_metrics": soc_metrics,
        "ga_results": ga_results,
        "selected_features": selected_features,
    })


# =====================================================================
# 2. MITRE ATT&CK MAPPING
# =====================================================================

def get_mitre_mapping(rule_name):
    """Mapează automat denumirea alertei la framework-ul MITRE ATT&CK."""
    name = (rule_name or "").upper()

    if any(k in name for k in ["DOS", "DDOS", "HULK", "SLOWLORIS"]):
        return {
            "tactic": "Impact",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "subtechnique": "Direct Network Flood",
        }
    elif any(k in name for k in ["PORTSCAN", "SCAN"]):
        return {
            "tactic": "Reconnaissance",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "subtechnique": "Port Scanning / Probing",
        }
    elif any(k in name for k in ["BRUTE", "SSH", "FTP"]):
        return {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "subtechnique": "Password Guessing",
        }
    elif any(k in name for k in ["WEB", "SQL", "XSS"]):
        return {
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "subtechnique": "Web Application Attack",
        }
    else:
        return {
            "tactic": "Defense Evasion / Execution",
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "subtechnique": "Binary Heuristic Detection",
        }


# =====================================================================
# 3. INGESTIE FLUXURI & DETECȚIE (CU AUTO-CONTAINMENT SOAR)
# =====================================================================

@csrf_exempt
def ingest_flow_api(request):
    """Endpoint REST unde simulatorul trimite fluxuri brute de rețea."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        data = json.loads(request.body)
    except Exception as e:
        return JsonResponse({'error': f'Invalid JSON: {e}'}, status=400)

    # 1. Salvare flux
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

    # 2. Pipeline Hibrid
    rule_result = evaluate_suricata_rules(data)

    if not rule_result.get("needs_ml", True):
        rule_name = rule_result.get("signature", "MATCHED_RULE")
        rule_score = rule_result.get("score", 0.8)
        ml_score = 0.0
        final_risk = rule_score
        severity = 'CRITICAL' if rule_score >= 0.85 else 'HIGH'
    else:
        ml_score, is_over_threshold = predict_anomaly(data)
        rule_name = "CLEAN (SURICATA_PASSED)"
        rule_score = 0.0
        final_risk = round(ml_score, 2)
        severity = 'HIGH' if is_over_threshold else 'LOW'

    # 3. Creare alertă
    alert = SecurityAlert.objects.create(
        flow=flow,
        rule_name=rule_name,
        rule_score=rule_score,
        anomaly_score=ml_score,
        final_risk=final_risk,
        severity=severity
    )

    # 4. [LOG AUTOMAT SOAR] Auto-Containment dacă riscul este critic
    if final_risk >= 0.90:
        if not BlockedIP.objects.filter(ip_address=flow.src_ip, is_active=True).exists():
            BlockedIP.objects.create(
                ip_address=flow.src_ip,
                reason=f"Auto-Mitigare SOAR: Risc critic ({final_risk}) - {rule_name}",
                expires_at=timezone.now() + timedelta(minutes=30),
                is_active=True
            )
            SOARActionLog.objects.create(
                action_type='FIREWALL_BLOCK',
                target=flow.src_ip,
                operator='SOAR Engine (Autonomous Playbook)',
                details=f"Prag critic depășit ({final_risk}). IP izolat automat pentru 30 minute."
            )

    # 5. Broadcast WebSocket
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


# =====================================================================
# 4. TRIAJ INCIDENT & EXPORT PDF
# =====================================================================

@require_http_methods(["GET"])
def alert_detail_api(request, alert_id):
    """Returnează datele complete ale incidentului pentru fereastra modală."""
    try:
        alert = SecurityAlert.objects.select_related('flow').get(id=alert_id)
        mitre = get_mitre_mapping(alert.rule_name)
        flow = alert.flow

        duration = getattr(flow, 'flow_duration', 0.0) or 0.0
        pps = getattr(flow, 'flow_packets_per_sec', None) or getattr(flow, 'flow_packets_s', 0.0) or 0.0
        bps = getattr(flow, 'flow_bytes_per_sec', None) or getattr(flow, 'flow_bytes_s', 0.0) or 0.0
        fwd_pkts = getattr(flow, 'total_fwd_packets', None) or getattr(flow, 'tot_fwd_pkts', 0)
        bwd_pkts = getattr(flow, 'total_backward_packets', None) or getattr(flow, 'tot_bwd_pkts', 0)

        data = {
            'id': alert.id,
            'timestamp': alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'rule_name': alert.rule_name,
            'severity': alert.severity,
            'final_risk': alert.final_risk,
            'anomaly_score': alert.anomaly_score,
            'flow_details': {
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'dst_port': flow.dst_port,
                'protocol': flow.protocol,
                'duration': round(float(duration), 4),
                'packets_per_sec': round(float(pps), 2),
                'bytes_per_sec': round(float(bps), 2),
                'fwd_pkts': fwd_pkts,
                'bwd_pkts': bwd_pkts,
            },
            'mitre': mitre
        }
        return JsonResponse(data)
    except SecurityAlert.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Alerta nu exista'}, status=404)


def export_incident_pdf_api(request, alert_id):
    """Generează raportul PDF al incidentului."""
    try:
        alert = SecurityAlert.objects.select_related('flow').get(id=alert_id)
    except SecurityAlert.DoesNotExist:
        raise Http404("Alerta nu a fost gasita.")

    flow = alert.flow
    flow_duration = getattr(flow, 'flow_duration', 0.0) or 0.0
    packets_per_sec = getattr(flow, 'flow_packets_per_sec', 0.0) or 0.0
    fwd_pkts = getattr(flow, 'total_fwd_packets', 'N/A')
    fwd_pkt_len_max = getattr(flow, 'fwd_packet_length_max', 0.0) or 0.0
    flow_iat_mean = getattr(flow, 'flow_iat_mean', 0.0) or 0.0
    flow_iat_max = getattr(flow, 'flow_iat_max', 0.0) or 0.0

    is_blocked = BlockedIP.objects.filter(
        ip_address=flow.src_ip,
        is_active=True,
        expires_at__gt=timezone.now()
    ).exists()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=18, leading=22, textColor=colors.HexColor('#0f172a'))
    subtitle_style = ParagraphStyle('DocSubtitle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748b'), spaceAfter=12)
    heading_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=11, leading=15, textColor=colors.HexColor('#1e293b'), spaceBefore=8, spaceAfter=5)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, leading=12, textColor=colors.HexColor('#334155'))

    elements = [
        Paragraph("RAPORT DE INVESTIGATIE INCIDENT SOC", title_style),
        Paragraph(f"Generat la: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Platforma NIDS Hibrida GA+CPLEX", subtitle_style),
        HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12)
    ]

    status_label = "BLOCAT (Firewall Drop)" if is_blocked else "MONITORIZAT (Activ)"
    summary_data = [
        [Paragraph("<b>ID Incident:</b>", body_style), Paragraph(f"#{alert.id}", body_style),
         Paragraph("<b>Severitate:</b>", body_style), Paragraph(f"<b>{alert.severity}</b>", body_style)],
        [Paragraph("<b>Data / Ora:</b>", body_style), Paragraph(alert.created_at.strftime('%Y-%m-%d %H:%M:%S'), body_style),
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
    elements.extend([summary_table, Spacer(1, 10)])

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
    elements.extend([Paragraph("1. Metadate Comunicatie Retea (5-Tuple)", heading_style), tuple_table, Spacer(1, 10)])

    features_data = [
        [Paragraph("<b>Trasatura Selectata</b>", body_style), Paragraph("<b>Valoare Incident</b>", body_style),
         Paragraph("<b>Medie Benign (Ref.)</b>", body_style), Paragraph("<b>Diagnostic Teoretic</b>", body_style)],
        [Paragraph("<code>Total Fwd Packets</code>", body_style), Paragraph(str(fwd_pkts), body_style),
         Paragraph("2 - 5 pachete", body_style), Paragraph("Volum conexiune forward", body_style)],
        [Paragraph("<code>Fwd Packet Length Max</code>", body_style), Paragraph(f"{float(fwd_pkt_len_max):.1f} octeti", body_style),
         Paragraph("&le; 250 octeti", body_style), Paragraph("Anomalie sarcina utila / payload", body_style)],
        [Paragraph("<code>Flow IAT Mean</code>", body_style), Paragraph(f"{float(flow_iat_mean):.2f} &micro;s", body_style),
         Paragraph("Variatie larga", body_style), Paragraph("Frecventa inter-sosire (burst rate)", body_style)],
        [Paragraph("<code>Flow IAT Max</code>", body_style), Paragraph(f"{float(flow_iat_max):.2f} &micro;s", body_style),
         Paragraph("Pauze prelungite", body_style), Paragraph("Detectare scanari low-and-slow", body_style)],
    ]
    features_table = Table(features_data, colWidths=[140, 100, 110, 170])
    features_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e0f2fe')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94a3b8')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.extend([
        Paragraph("2. Analiza Trasaturilor Optime (Sub-spatiu Calibrat GA + CPLEX)", heading_style),
        features_table,
        Spacer(1, 10)
    ])

    recom_text = """
    &bull; <b>Izolare la nivelul perimetrului:</b> Mentinerea adresei IP in lista de blocare a firewall-ului.<br/>
    &bull; <b>Analiza corelata:</b> Verificarea jurnalelor DNS si a cererilor HTTP catre portul tinta.<br/>
    &bull; <b>Triage intern:</b> Inspectarea statiilor de lucru interne daca IP-ul destinatie gazduieste servicii critice.
    """
    elements.extend([
        Paragraph("3. Actiuni Recomandate & Raspuns la Incident (SOAR)", heading_style),
        Paragraph(recom_text, body_style),
        Spacer(1, 12),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cbd5e1'), spaceAfter=6),
        Paragraph("Raport generat automat de platforma de securitate. Validat pentru audit.", ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#94a3b8')))
    ])

    doc.build(elements)
    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="incident_report_{alert.id}.pdf"'
    return response


# =====================================================================
# 5. FIREWALL ACL & SOAR ACTIONS (BLOCARE / DEBLOCARE CU AUDIT LOG)
# =====================================================================

@csrf_exempt
@require_POST
def block_ip_api(request):
    """Adaugă manual un IP în firewall și înregistrează acțiunea în audit."""
    try:
        data = json.loads(request.body.decode('utf-8'))
        ip = data.get('ip', '').strip()
        reason = data.get('reason', 'Blocare manuala din investigatie SOC')
        duration_minutes = int(data.get('duration_minutes', 60))

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

        # Înregistrare în Audit Trail
        SOARActionLog.objects.create(
            action_type='FIREWALL_BLOCK',
            target=ip,
            operator='SOC Analyst (Manual Containment)',
            details=f"Blocare pe Firewall: {reason} (TTL: {duration_minutes}m)"
        )

        return JsonResponse({
            'status': 'success',
            'created': created,
            'ip': blocked_entry.ip_address,
            'message': f"IP-ul {ip} a fost adăugat în regulile de firewall."
        })
    except Exception as e:
        return JsonResponse({'status': 'error', 'details': str(e)}, status=500)


@require_GET
def get_blocked_ips_api(request):
    """Returnează regulile active de blocare și curăță regulile expirate."""
    now = timezone.now()

    # Curățare reguli expirate + Logare curățare
    expired_rules = BlockedIP.objects.filter(expires_at__lte=now, is_active=True)
    for rule in expired_rules:
        SOARActionLog.objects.create(
            action_type='FIREWALL_UNBLOCK',
            target=rule.ip_address,
            operator='SOAR Scheduler (Rule Janitor)',
            details=f"Perioada de reținere (TTL) a expirat. IP deblocat automat."
        )
    expired_rules.update(is_active=False)

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
    """Deblochează manual un IP din firewall și înregistrează acțiunea în audit."""
    try:
        data = json.loads(request.body.decode('utf-8'))
        ip = data.get('ip', '').strip()

        if not ip:
            return JsonResponse({'status': 'error', 'message': 'Adresa IP lipseste.'}, status=400)

        updated_count = BlockedIP.objects.filter(ip_address=ip, is_active=True).update(is_active=False)

        if updated_count > 0:
            SOARActionLog.objects.create(
                action_type='FIREWALL_UNBLOCK',
                target=ip,
                operator='SOC Analyst (Manual Release)',
                details="Deblocare manuală din consola de securitate"
            )
            return JsonResponse({'status': 'success', 'message': f"IP-ul {ip} a fost deblocat."})
        else:
            return JsonResponse({'status': 'warning', 'message': f"IP-ul {ip} nu era blocat activ."})
    except Exception as e:
        return JsonResponse({'status': 'error', 'details': str(e)}, status=500)


@require_GET
def audit_logs_api(request):
    """Returnează ultimele 20 de acțiuni înregistrate de SOAR și analist."""
    logs = SOARActionLog.objects.all().order_by('-created_at')[:20]
    data = [
        {
            'id': l.id,
            'timestamp': l.created_at.strftime('%H:%M:%S'),
            'date': l.created_at.strftime('%Y-%m-%d'),
            'action_type': l.action_type,
            'target': l.target,
            'operator': l.operator,
            'details': l.details or '-'
        }
        for l in logs
    ]
    return JsonResponse({'status': 'success', 'logs': data})


# =====================================================================
# 6. SANDBOX PE & FUZIUNE XDR (CU AUDIT LOG)
# =====================================================================

@csrf_exempt
@require_POST
def inspect_artifact_api(request):
    """Rulează analiza statică PE asupra fișierului încărcat și loghează rezultatul."""
    try:
        uploaded_file = request.FILES.get('file')
        alert_id = request.POST.get('alert_id')

        if not uploaded_file:
            return JsonResponse({'status': 'error', 'message': 'Niciun fisier nu a fost transmis.'}, status=400)

        raw_data = uploaded_file.read()
        analysis = analyze_pe_bytes(raw_data, file_name=uploaded_file.name)

        target_alert = None
        if alert_id:
            try:
                target_alert = SecurityAlert.objects.select_related('flow').get(id=alert_id)
            except SecurityAlert.DoesNotExist:
                pass

        artifact = InspectedArtifact.objects.create(
            alert=target_alert,
            file_name=analysis["file_name"],
            sha256=analysis["sha256"],
            md5=analysis["md5"],
            entropy=analysis["entropy"],
            verdict=analysis["verdict"],
            file_risk_score=analysis["file_risk_score"],
            findings_json=json.dumps(analysis["findings"])
        )

        # [LOG AUTOMAT SOAR] Logare inspecție binar
        SOARActionLog.objects.create(
            action_type='SANDBOX_ANALYSIS',
            target=uploaded_file.name,
            operator='XDR Binary Inspector',
            details=f"Verdict: {analysis['verdict']} | Entropie: {analysis['entropy']} | Risc: {analysis['file_risk_score']}"
        )

        mitigated = False
        if target_alert:
            net_score = target_alert.final_risk
            file_score = analysis["file_risk_score"]
            # Fuziune ponderată: 50% rețea + 50% fișier (corecție sintaxă *)
            fused_risk = round((0.5 * net_score) + (0.5 * file_score), 2)
            target_alert.final_risk = fused_risk

            if fused_risk >= 0.85:
                target_alert.severity = "CRITICAL"
                src_ip = target_alert.flow.src_ip
                BlockedIP.objects.update_or_create(
                    ip_address=src_ip,
                    defaults={
                        'reason': f"Fuziune XDR: Retea ({net_score}) + Fisier ({file_score}) -> {analysis['file_name']}",
                        'expires_at': timezone.now() + timedelta(minutes=60),
                        'is_active': True
                    }
                )
                SOARActionLog.objects.create(
                    action_type='FIREWALL_BLOCK',
                    target=src_ip,
                    operator='SOAR Playbook (XDR Fusion Containment)',
                    details=f"Risc fuzionat critic ({fused_risk}). IP {src_ip} blocat automat."
                )
                mitigated = True

            target_alert.save()

        return JsonResponse({
            'status': 'success',
            'artifact_id': artifact.id,
            'analysis': analysis,
            'mitigated_automatically': mitigated,
            'message': f"Fisierul {analysis['file_name']} a fost inspectat cu succes."
        })

    except Exception as e:
        return JsonResponse({'status': 'error', 'details': str(e)}, status=500)


# =====================================================================
# 7. GENERARE GRAFICE LA CERERE
# =====================================================================

@csrf_exempt
@require_POST
def trigger_evaluation_api(request):
    """Execută scriptul de recalculare la cerere din UI."""
    try:
        script_name = "evaluate_models.py" if os.path.exists(os.path.join(settings.BASE_DIR, "evaluate_models.py")) else "generate_thesis_charts.py"
        script_path = os.path.join(settings.BASE_DIR, script_name)

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