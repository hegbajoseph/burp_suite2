"""
Views pour le scanner de vulnérabilités
"""

import json
import os
import threading
import traceback

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from .models import ScanTarget, ScanIssue
from .scanner_engine import VulnerabilityScanner  # ← corrigé (plus de triple 'n')


# ─── Cache de progression en mémoire ─────────────────────────────────────────
_scan_progress = {}


def _progress_callback(scan_id, step, message):
    _scan_progress[str(scan_id)] = {'step': step, 'message': message}


def _run_scan_thread(scan_id, url):
    """Lancer le scan dans un thread séparé."""
    try:
        scanner = VulnerabilityScanner(scan_id, progress_callback=_progress_callback)
        results = scanner.scan(url)
        scan_obj = ScanTarget.objects.get(id=scan_id)

        if results['status'] == 'completed':
            summary = results.get('summary', {})
            scan_obj.status = 'completed'
            scan_obj.completed_at = timezone.now()
            scan_obj.total_issues = results.get('total_issues', 0)
            scan_obj.high_issues = summary.get('high', 0)
            scan_obj.medium_issues = summary.get('medium', 0)
            scan_obj.low_issues = summary.get('low', 0)
            scan_obj.save()

            for issue_data in results.get('issues', []):
                ScanIssue.objects.create(
                    scan=scan_obj,
                    issue_type=issue_data.get('issue_type', 'info'),
                    severity=issue_data.get('severity', 'info'),
                    title=issue_data.get('title', ''),
                    description=issue_data.get('description', ''),
                    url=issue_data.get('url', url),
                    parameter=issue_data.get('parameter', ''),
                    payload=issue_data.get('payload', ''),
                    evidence=issue_data.get('evidence', ''),
                    remediation=issue_data.get('remediation', ''),
                )
        else:
            scan_obj.status = 'failed'
            scan_obj.save()

    except Exception as e:
        traceback.print_exc()
        try:
            scan_obj = ScanTarget.objects.get(id=scan_id)
            scan_obj.status = 'failed'
            scan_obj.save()
        except Exception:
            pass


# ─── Scanner Views ────────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
def start_scan(request):
    """Démarrer un nouveau scan."""
    try:
        data = json.loads(request.body)
        url = data.get('url', '').strip()

        if not url:
            return JsonResponse({'error': 'URL requise'}, status=400)

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        scan = ScanTarget.objects.create(url=url, status='running')
        thread = threading.Thread(
            target=_run_scan_thread,
            args=(scan.id, url),
            daemon=True
        )
        thread.start()

        return JsonResponse({
            'scan_id': str(scan.id),
            'url': url,
            'status': 'running',
            'message': 'Scan démarré avec succès',
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'JSON invalide'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def scan_progress(request, scan_id):
    """Progression du scan en cours."""
    progress = _scan_progress.get(str(scan_id), {'step': 0, 'message': 'En attente...'})
    try:
        scan = ScanTarget.objects.get(id=scan_id)
        return JsonResponse({
            'scan_id': str(scan_id),
            'status': scan.status,
            'progress': progress['step'],
            'message': progress['message'],
        })
    except ScanTarget.DoesNotExist:
        return JsonResponse({'error': 'Scan introuvable'}, status=404)


@require_http_methods(["GET"])
def scan_results(request, scan_id):
    """Résultats complets d'un scan."""
    scan = get_object_or_404(ScanTarget, id=scan_id)
    issues = [
        {
            'id': str(i.id),
            'issue_type': i.issue_type,
            'severity': i.severity,
            'title': i.title,
            'description': i.description,
            'url': i.url,
            'parameter': i.parameter,
            'payload': i.payload,
            'evidence': i.evidence,
            'remediation': i.remediation,
        }
        for i in scan.issues.all()
    ]
    return JsonResponse({
        'scan_id': str(scan.id),
        'url': scan.url,
        'status': scan.status,
        'created_at': scan.created_at.isoformat(),
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'total_issues': scan.total_issues,
        'high_issues': scan.high_issues,
        'medium_issues': scan.medium_issues,
        'low_issues': scan.low_issues,
        'issues': issues,
    })


@require_http_methods(["GET"])
def recent_scans(request):
    """Scans récents pour le dashboard."""
    scans = ScanTarget.objects.all().order_by('-created_at')[:10]
    return JsonResponse({'scans': [
        {
            'id': str(s.id),
            'url': s.url,
            'status': s.status,
            'total_issues': s.total_issues,
            'high_issues': s.high_issues,
            'created_at': s.created_at.isoformat(),
        }
        for s in scans
    ]})


@require_http_methods(["DELETE"])
def delete_scan(request, scan_id):
    """Supprimer un scan."""
    scan = get_object_or_404(ScanTarget, id=scan_id)
    scan.delete()
    return JsonResponse({'message': 'Scan supprimé'})


# ─── Proxy Views ──────────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
def intercept_toggle(request):
    state_file = os.path.join(os.path.dirname(__file__), 'intercept_state.txt')
    try:
        with open(state_file, 'r') as f:
            current = f.read().strip() == 'true'
    except FileNotFoundError:
        current = False
    new_state = not current
    with open(state_file, 'w') as f:
        f.write('true' if new_state else 'false')
    return JsonResponse({'enabled': new_state})