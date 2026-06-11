from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Count
import json
import base64
import urllib.parse
import html
import hashlib
import requests
import threading
import time
import os

from .models import (
    ScanTarget, ScanResult, ProxyRequest,
    IntruderPayload, RepeaterRequest, SpiderResult, DecoderData,
)

from . import middleware as mw


# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────

def dashboard(request):
    stats = {
        'total_scans':    ScanTarget.objects.count(),
        'active_scans':   ScanTarget.objects.filter(status='running').count(),
        'total_issues':   ScanResult.objects.count(),
        'high_issues':    ScanResult.objects.filter(severity='high').count(),
        'medium_issues':  ScanResult.objects.filter(severity='medium').count(),
        'low_issues':     ScanResult.objects.filter(severity='low').count(),
        'proxy_requests': ProxyRequest.objects.count(),
        'spider_urls':    SpiderResult.objects.count(),
    }
    # ScanResult a bien une FK 'target' → select_related OK
    recent_scans_list  = ScanTarget.objects.all()[:5]
    recent_issues_list = ScanResult.objects.select_related('target').all()[:10]
    return render(request, 'burp/dashboard.html', {
        'stats':         stats,
        'recent_scans':  recent_scans_list,
        'recent_issues': recent_issues_list,
        'page':          'dashboard',
    })


# ─────────────────────────────────────────────
# SCANNER
# ─────────────────────────────────────────────

def scanner(request):
    scans  = ScanTarget.objects.all()
    # ScanResult.target existe → select_related valide
    issues = ScanResult.objects.select_related('target').all()[:20]
    return render(request, 'burp/scanner.html', {
        'scans':  scans,
        'issues': issues,
        'page':   'scanner',
    })


@csrf_exempt
def start_scan(request):
    if request.method == 'POST':
        content_type = request.content_type or ''
        if 'application/json' in content_type:
            data      = json.loads(request.body)
            url       = data.get('url', '').strip()
            name      = data.get('name', url)
            scan_type = data.get('scan_type', 'full')       # 'full' | 'passive' | 'active'
            areas     = data.get('areas', [])               # ['sqli', 'xss', 'csrf', ...]
        else:
            url       = request.POST.get('url', '').strip()
            name      = request.POST.get('name', url)
            scan_type = request.POST.get('scan_type', 'full')
            areas     = request.POST.getlist('areas')       # checkboxes
 
        if not url:
            return JsonResponse({'error': 'URL requise'}, status=400)
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
 
        target = ScanTarget.objects.create(url=url, name=name, status='running')
        thread = threading.Thread(
            target=_run_scan,
            args=(target.id, url, scan_type, areas),
            daemon=True,
        )
        thread.start()
 
        if 'application/json' in content_type:
            return JsonResponse({
                'id':        str(target.id),
                'status':    'running',
                'scan_type': scan_type,
                'areas':     areas,
            })
        return redirect('burp:scanner')
 
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)



def _run_scan(target_id, url, scan_type='full', scan_areas=None):
    """Lance le vrai scanner avec les paramètres choisis dans la modale."""
    try:
        from .scanner_enginine import VulnerabilityScanner
 
        target  = ScanTarget.objects.get(id=target_id)
        scanner = VulnerabilityScanner(
            scan_id=target_id,
            progress_callback=_progress_callback,
        )
 
        # Passer scan_type et scan_areas au moteur
        results = scanner.scan(url, scan_type=scan_type, scan_areas=scan_areas)
 
        if results['status'] == 'completed':
            summary = results.get('summary', {})
            target.status        = 'completed'
            target.completed_at  = timezone.now()
            target.total_issues  = results.get('total_issues', 0)
            target.high_issues   = summary.get('high', 0)
            target.medium_issues = summary.get('medium', 0)
            target.low_issues    = summary.get('low', 0)
            target.save()
 
            for issue in results.get('issues', []):
                ScanResult.objects.create(
                    target=target,
                    url=issue.get('url', url),
                    issue_type=issue.get('issue_type', 'info'),
                    severity=issue.get('severity', 'info'),
                    parameter=issue.get('parameter', ''),
                    description=issue.get('description', ''),
                    evidence=issue.get('evidence', ''),
                    remediation=issue.get('remediation', ''),
                )
        else:
            target.status = 'failed'
            target.save()
 
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        import traceback
        traceback.print_exc()
        try:
            t = ScanTarget.objects.get(id=target_id)
            t.status = 'failed'
            t.save()
        except Exception:
            pass

@csrf_exempt
def scan_status(request, scan_id):
    target  = get_object_or_404(ScanTarget, id=scan_id)
    results = list(target.results.values('id', 'issue_type', 'severity', 'url', 'parameter'))
    return JsonResponse({
        'status':        target.status,
        'results_count': len(results),
        'results':       results,
    })


def scan_detail(request, scan_id):
    target          = get_object_or_404(ScanTarget, id=scan_id)
    results         = target.results.all()
    severity_counts = results.values('severity').annotate(count=Count('severity'))
    return render(request, 'burp/scan_detail.html', {
        'target':          target,
        'results':         results,
        'severity_counts': severity_counts,
        'page':            'scanner',
    })


@csrf_exempt
@require_http_methods(["DELETE"])
def delete_scan(request, scan_id):
    target = get_object_or_404(ScanTarget, id=scan_id)
    target.delete()
    return JsonResponse({'success': True})


# ─────────────────────────────────────────────
# API SCANNER
# ─────────────────────────────────────────────

_scan_progress = {}


def _progress_callback(scan_id, step, message):
    _scan_progress[str(scan_id)] = {'step': step, 'message': message}


@require_http_methods(["GET"])
def scan_progress(request, scan_id):
    progress = _scan_progress.get(str(scan_id), {'step': 0, 'message': 'En attente...'})
    try:
        scan = ScanTarget.objects.get(id=scan_id)
        return JsonResponse({
            'scan_id':  str(scan_id),
            'status':   scan.status,
            'progress': progress['step'],
            'message':  progress['message'],
        })
    except ScanTarget.DoesNotExist:
        return JsonResponse({'error': 'Scan introuvable'}, status=404)


@require_http_methods(["GET"])
def scan_results(request, scan_id):
    try:
        scan = ScanTarget.objects.get(id=scan_id)
    except ScanTarget.DoesNotExist:
        return JsonResponse({'error': 'Scan introuvable'}, status=404)

    issues = [
        {
            'id':          str(i.id),
            'issue_type':  i.issue_type,
            'severity':    i.severity,
            'description': i.description,
            'url':         i.url,
            'parameter':   i.parameter,
            'evidence':    i.evidence,
            'remediation': i.remediation,
        }
        for i in scan.results.all()
    ]
    return JsonResponse({
        'scan_id':      str(scan.id),
        'url':          scan.url,
        'status':       scan.status,
        'total_issues': scan.total_issues,
        'high_issues':  scan.high_issues,
        'issues':       issues,
    })


@require_http_methods(["GET"])
def recent_scans(request):
    scans = ScanTarget.objects.all().order_by('-created_at')[:10]
    return JsonResponse({'scans': [
        {
            'id':           str(s.id),
            'url':          s.url,
            'status':       s.status,
            'total_issues': s.total_issues,
            'high_issues':  s.high_issues,
            'created_at':   s.created_at.isoformat(),
        }
        for s in scans
    ]})


# ─────────────────────────────────────────────
# PROXY
# ─────────────────────────────────────────────

def proxy(request):
    proxy_reqs = ProxyRequest.objects.all()[:100]
    return render(request, 'burp/proxy.html', {
        'proxy_requests': proxy_reqs,
        'page':           'proxy',
    })


@csrf_exempt
@require_http_methods(["POST"])
def intercept_toggle(request):
    """Activer / désactiver l'interception du proxy."""
    intercept_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'intercept_state.txt')
    try:
        with open(intercept_file, 'r') as f:
            current = f.read().strip() == 'true'
    except FileNotFoundError:
        current = False
    new_state = not current
    with open(intercept_file, 'w') as f:
        f.write('true' if new_state else 'false')
    print(f"[Django] Intercept: {new_state}")
    return JsonResponse({'enabled': new_state})


@csrf_exempt
def intercept_status(request):
    intercept_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'intercept_state.txt')
    try:
        with open(intercept_file, 'r') as f:
            enabled = f.read().strip() == 'true'
    except FileNotFoundError:
        enabled = False
    return JsonResponse({'enabled': enabled})


@csrf_exempt
@require_http_methods(["POST"])
def intercept_request(request):
    data = json.loads(request.body)
    # ProxyRequest : champs réels = method, url, headers, body, intercepted
    pr = ProxyRequest.objects.create(
        method=data.get('method', 'GET'),
        url=data.get('url', ''),
        headers=json.dumps(data.get('headers', {})),
        body=data.get('body', ''),
        intercepted=True,
    )
    return JsonResponse({'id': pr.id, 'status': 'intercepted'})


@csrf_exempt
def forward_request(request, req_id):
    pr = get_object_or_404(ProxyRequest, id=req_id)
    try:
        pending_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pending_requests.json')
        forward_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forward_signal.txt')
        proxy_key = None
        try:
            with open(pending_file, 'r') as f:
                pending = json.load(f)
            for key, entry in pending.items():
                if entry.get('django_id') == req_id:
                    proxy_key = key
                    break
            if not proxy_key and pending:
                proxy_key = list(pending.keys())[0]
        except Exception as e:
            print(f"[Django] Read pending error: {e}")
        if proxy_key:
            with open(forward_file, 'w') as f:
                f.write(proxy_key)
        pr.intercepted = False
        pr.save()
        return JsonResponse({'status': 'forwarded', 'id': req_id})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def drop_request(request, req_id):
    pr = get_object_or_404(ProxyRequest, id=req_id)
    pending_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pending_requests.json')
    drop_file    = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'drop_signal.txt')
    proxy_key = None
    try:
        with open(pending_file, 'r') as f:
            pending = json.load(f)
        for key, entry in pending.items():
            if entry.get('django_id') == req_id:
                proxy_key = key
                break
        if not proxy_key and pending:
            proxy_key = list(pending.keys())[0]
    except Exception:
        pass
    if proxy_key:
        with open(drop_file, 'w') as f:
            f.write(proxy_key)
    pr.delete()
    return JsonResponse({'status': 'dropped'})


def proxy_history(request):
    # Champs réels de ProxyRequest (pas de host/path/request_headers séparés)
    reqs = ProxyRequest.objects.all().values(
        'id', 'method', 'url', 'headers', 'body',
        'response_status', 'response_headers',
        'response_body', 'response_time',
        'intercepted', 'timestamp',
    )
    return JsonResponse({'requests': list(reqs)})


@csrf_exempt
@require_http_methods(["POST", "DELETE"])
def clear_proxy_history(request):
    deleted_count, _ = ProxyRequest.objects.all().delete()
    return JsonResponse({
        'success': True,
        'deleted': deleted_count,
        'message': f'{deleted_count} requête(s) supprimée(s).',
    })


@csrf_exempt
@require_http_methods(["DELETE"])
def delete_proxy_request(request, req_id):
    pr = get_object_or_404(ProxyRequest, id=req_id)
    pr.delete()
    return JsonResponse({'success': True, 'id': req_id})


@csrf_exempt
@require_http_methods(["POST"])
def add_proxy_request(request):
    data = json.loads(request.body)
    pr = ProxyRequest.objects.create(
        method=data.get('method', 'GET'),
        url=data.get('url', ''),
        headers=json.dumps(data.get('headers', {'User-Agent': 'BurpSuite-Django/1.0'})),
        body=data.get('body', ''),
        response_status=data.get('response_status', 200),
        response_time=data.get('response_time', 0.45),
    )
    return JsonResponse({'id': pr.id})


@csrf_exempt
@require_http_methods(["POST"])
def modify_and_forward(request, req_id):
    pr = get_object_or_404(ProxyRequest, id=req_id)
    try:
        data = json.loads(request.body)
    except Exception:
        data = {}
    if 'body' in data:
        pr.body = data['body']
    pr.intercepted = False
    pr.save()

    pending_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pending_requests.json')
    forward_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forward_signal.txt')
    try:
        with open(pending_file, 'r') as f:
            pending = json.load(f)
        proxy_key = None
        for key, entry in pending.items():
            if entry.get('django_id') == req_id:
                proxy_key = key
                break
        if not proxy_key and pending:
            proxy_key = list(pending.keys())[0]
        if proxy_key:
            with open(forward_file, 'w') as f:
                f.write(proxy_key)
            return JsonResponse({'status': 'forwarded', 'id': req_id})
        return JsonResponse({'status': 'not_found', 'id': req_id})
    except Exception as e:
        print(f"[Django] Forward error: {e}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def release_request(request, req_id):
    pr = get_object_or_404(ProxyRequest, id=req_id)
    pending_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pending_requests.json')
    drop_file    = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'drop_signal.txt')
    proxy_key = None
    try:
        with open(pending_file, 'r') as f:
            pending = json.load(f)
        for key, entry in pending.items():
            if entry.get('django_id') == req_id:
                proxy_key = key
                break
        if not proxy_key and pending:
            proxy_key = list(pending.keys())[0]
    except Exception:
        pass
    if proxy_key:
        with open(drop_file, 'w') as f:
            f.write(proxy_key)
    pr.delete()
    return JsonResponse({'status': 'dropped'})


@csrf_exempt
def proxy_action(request):
    if request.method == 'POST':
        data   = json.loads(request.body)
        action = data.get('action')
        from . import proxy_server
        if action == 'toggle_intercept':
            proxy_server.intercept_enabled = data.get('enabled', False)
            return JsonResponse({'status': 'ok', 'intercept': proxy_server.intercept_enabled})
    return JsonResponse({'error': 'invalid'}, status=400)


# ─────────────────────────────────────────────
# INTRUDER
# ─────────────────────────────────────────────

def intruder(request):
    payloads = IntruderPayload.objects.all()
    return render(request, 'burp/intruder.html', {'payloads': payloads, 'page': 'intruder'})


@csrf_exempt
@require_http_methods(["POST"])
def run_intruder(request):
    data = json.loads(request.body)
    # IntruderPayload.payloads est un TextField → sérialiser en JSON string
    payload_obj = IntruderPayload.objects.create(
        name=data.get('name', 'Attack'),
        attack_type=data.get('attack_type', 'sniper'),
        target_url=data.get('target_url', ''),
        body=data.get('body', ''),
        payloads=json.dumps(data.get('payloads', [])),
        status='running',
    )
    thread = threading.Thread(target=_run_intruder, args=(payload_obj.id,), daemon=True)
    thread.start()
    return JsonResponse({'id': payload_obj.id, 'status': 'running'})


def _run_intruder(payload_id):
    try:
        payload_obj   = IntruderPayload.objects.get(id=payload_id)
        payloads_list = json.loads(payload_obj.payloads or '[]')
        results = []
        for i, payload in enumerate(payloads_list[:20]):
            time.sleep(0.1)
            results.append({
                'payload':     payload,
                'status':      200 if i % 3 != 0 else 500,
                'length':      1024 + (i * 23),
                'time':        round(0.1 + (i * 0.05), 3),
                'interesting': i % 5 == 0,
            })
        payload_obj.results = json.dumps(results)
        payload_obj.status  = 'completed'
        payload_obj.save()
    except Exception as e:
        print(f"[INTRUDER ERROR] {e}")


@csrf_exempt
def intruder_status(request, intruder_id):
    obj     = get_object_or_404(IntruderPayload, id=intruder_id)
    results = json.loads(obj.results or '[]')
    return JsonResponse({
        'status':        obj.status,
        'results':       results,
        'results_count': len(results),
    })


def add_payload(request):
    if request.method == 'POST':
        payload = request.POST.get('payload')
        print("Payload ajouté :", payload)
    return render(request, 'burp/intruder.html')


# ─────────────────────────────────────────────
# REPEATER
# ─────────────────────────────────────────────

def repeater(request):
    items = RepeaterRequest.objects.all()
    return render(request, 'burp/repeater.html', {
        'repeater_requests': items,
        'page':              'repeater',
    })


@csrf_exempt
@require_http_methods(["POST"])
def send_repeater(request):
    data   = json.loads(request.body)
    req_id = data.get('id')
    if req_id:
        rr         = get_object_or_404(RepeaterRequest, id=req_id)
        rr.method  = data.get('method', rr.method)
        rr.url     = data.get('url', rr.url)
        rr.headers = json.dumps(data.get('headers', json.loads(rr.headers or '{}')))
        rr.body    = data.get('body', rr.body)
    else:
        rr = RepeaterRequest(
            name=data.get('name', 'Request'),
            method=data.get('method', 'GET'),
            url=data.get('url', ''),
            headers=json.dumps(data.get('headers', {})),
            body=data.get('body', ''),
        )
    try:
        headers_dict = json.loads(rr.headers or '{}')
        start = time.time()
        resp  = requests.request(
            method=rr.method, url=rr.url,
            headers=headers_dict, data=rr.body,
            timeout=15, verify=False,
        )
        elapsed             = time.time() - start
        rr.response_status  = resp.status_code
        rr.response_headers = json.dumps(dict(resp.headers))
        rr.response_body    = resp.text[:50000]
        rr.response_time    = round(elapsed, 3)
        rr.save()
        return JsonResponse({
            'id':               rr.id,
            'response_status':  resp.status_code,
            'response_headers': dict(resp.headers),
            'response_body':    resp.text[:50000],
            'response_time':    round(elapsed, 3),
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ─────────────────────────────────────────────
# SPIDER
# ─────────────────────────────────────────────

def spider(request):
    targets = ScanTarget.objects.all()
    # SpiderResult n'a PAS de FK → pas de select_related
    results = SpiderResult.objects.all()[:200]
    return render(request, 'burp/spider.html', {
        'targets': targets,
        'results': results,
        'page':    'spider',
    })


@csrf_exempt
@require_http_methods(["POST"])
def start_spider(request):
    data = json.loads(request.body)
    url  = data.get('url', '').strip()
    if not url:
        return JsonResponse({'error': 'URL requise'}, status=400)
    target, _ = ScanTarget.objects.get_or_create(
        url=url, defaults={'name': url, 'status': 'running'}
    )
    thread = threading.Thread(target=_run_spider, args=(target.id, url), daemon=True)
    thread.start()
    return JsonResponse({'id': str(target.id), 'status': 'running'})


def _run_spider(target_id, base_url):
    """SpiderResult n'a pas de FK target → champs disponibles : url, status_code, content_type, title."""
    try:
        base = base_url.rstrip('/')
        simulated = [
            (base + '/',           200, 'text/html',        'Home'),
            (base + '/login',      200, 'text/html',        'Login'),
            (base + '/api/users',  401, 'application/json', 'API Users'),
            (base + '/admin',      302, 'text/html',        'Admin'),
            (base + '/robots.txt', 200, 'text/plain',       'Robots'),
        ]
        for url, status, ctype, title in simulated:
            time.sleep(0.3)
            SpiderResult.objects.create(
                url=url,
                status_code=status,
                content_type=ctype,
                title=title,
            )
        target = ScanTarget.objects.get(id=target_id)
        target.status = 'completed'
        target.save()
    except Exception as e:
        print(f"[SPIDER ERROR] {e}")


# ─────────────────────────────────────────────
# DECODER
# ─────────────────────────────────────────────

def decoder(request):
    history = DecoderData.objects.all()[:20]
    return render(request, 'burp/decoder.html', {'history': history, 'page': 'decoder'})


@csrf_exempt
@require_http_methods(["POST"])
def decode_encode(request):
    data       = json.loads(request.body)
    input_data = data.get('input', '')
    encoding   = data.get('encoding', 'base64')
    operation  = data.get('operation', 'decode')
    try:
        if encoding == 'base64':
            output = (
                base64.b64decode(input_data.encode()).decode('utf-8', errors='replace')
                if operation == 'decode'
                else base64.b64encode(input_data.encode()).decode()
            )
        elif encoding == 'url':
            output = urllib.parse.unquote(input_data) if operation == 'decode' else urllib.parse.quote(input_data)
        elif encoding == 'html':
            output = html.unescape(input_data) if operation == 'decode' else html.escape(input_data)
        elif encoding == 'hex':
            output = (
                bytes.fromhex(input_data.replace(' ', '')).decode('utf-8', errors='replace')
                if operation == 'decode'
                else input_data.encode().hex()
            )
        elif encoding == 'binary':
            if operation == 'decode':
                b      = input_data.replace(' ', '')
                output = ''.join(chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8))
            else:
                output = ' '.join(format(ord(c), '08b') for c in input_data)
        elif encoding == 'md5':
            output = hashlib.md5(input_data.encode()).hexdigest()
        elif encoding == 'sha256':
            output = hashlib.sha256(input_data.encode()).hexdigest()
        else:
            output = input_data

        DecoderData.objects.create(
            input_data=input_data[:1000],
            output_data=output[:1000],
            encoding_type=encoding,
            operation=operation,
        )
        return JsonResponse({'output': output, 'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e), 'success': False}, status=400)


# ─────────────────────────────────────────────
# COMPARER
# ─────────────────────────────────────────────

def comparer(request):
    return render(request, 'burp/comparer.html', {'page': 'comparer'})


@csrf_exempt
@require_http_methods(["POST"])
def compare_data(request):
    data   = json.loads(request.body)
    lines1 = data.get('text1', '').splitlines()
    lines2 = data.get('text2', '').splitlines()
    diffs  = []
    for i in range(max(len(lines1), len(lines2))):
        l1 = lines1[i] if i < len(lines1) else ''
        l2 = lines2[i] if i < len(lines2) else ''
        diffs.append({'line': i + 1, 'left': l1, 'right': l2, 'changed': l1 != l2})
    return JsonResponse({
        'diffs':         diffs,
        'total_lines':   len(diffs),
        'changed_lines': sum(1 for d in diffs if d['changed']),
    })