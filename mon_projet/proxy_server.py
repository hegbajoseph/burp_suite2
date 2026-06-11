import socket
import threading
import time
import os
import sys
import json
from urllib.parse import urlparse

PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8080
pending_requests = {}

INTERCEPT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'intercept_state.txt')
PENDING_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pending_requests.json')
FORWARD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forward_signal.txt')
DROP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'drop_signal.txt')


def is_intercept_enabled():
    try:
        with open(INTERCEPT_FILE, 'r') as f:
            return f.read().strip() == 'true'
    except:
        return False


def save_pending():
    try:
        data = {}
        for k, v in pending_requests.items():
            data[k] = {
                'django_id': v.get('django_id'),
                'req': {
                    'id': v['req']['id'],
                    'method': v['req']['method'],
                    'path': v['req']['path'],
                    'host': v['req']['host'],
                }
            }
        with open(PENDING_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"[Proxy] Save pending error: {e}")


def check_signal(req_id):
    try:
        with open(FORWARD_FILE, 'r') as f:
            signal_key = f.read().strip()
        if signal_key == req_id:
            try:
                os.remove(FORWARD_FILE)
            except:
                pass
            print(f"[Proxy] Signal FORWARD recu: {req_id}")
            return 'forward'
    except:
        pass
    try:
        with open(DROP_FILE, 'r') as f:
            signal_key = f.read().strip()
        if signal_key == req_id:
            try:
                os.remove(DROP_FILE)
            except:
                pass
            print(f"[Proxy] Signal DROP recu: {req_id}")
            return 'drop'
    except:
        pass
    return None


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tuto.settings')

django_ready = False


def setup_django():
    global django_ready
    if django_ready:
        return True
    try:
        import django
        django.setup()
        django_ready = True
        print("[Proxy] Django OK")
        return True
    except Exception as e:
        print(f"[Proxy] Django setup error: {e}")
        return False


def parse_request(data):
    try:
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = len(data)
        headers_raw = data[:header_end].decode('utf-8', errors='replace')
        lines = headers_raw.split('\r\n')
        if not lines:
            return None
        parts = lines[0].split(' ', 2)
        if len(parts) < 2:
            return None
        method = parts[0]
        raw_path = parts[1]
        version = parts[2] if len(parts) > 2 else 'HTTP/1.1'

        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers[k] = v

        host = headers.get('Host', '')

        if raw_path.startswith('http://') or raw_path.startswith('https://'):
            parsed = urlparse(raw_path)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
        else:
            path = raw_path

        body = data[header_end + 4:].decode('utf-8', errors='replace') if header_end < len(data) else ''

        return {
            'id': str(time.time()),
            'method': method,
            'path': path,
            'host': host,
            'version': version,
            'headers': headers,
            'body': body,
            'raw': f"{method} {path} {version}\r\n" + '\r\n'.join(f"{k}: {v}" for k, v in headers.items()),
            'timestamp': time.strftime('%H:%M:%S'),
        }
    except Exception as e:
        print(f"[Proxy] Parse error: {e}")
        return None


def rebuild_request(req):
    lines = f"{req['method']} {req['path']} {req['version']}\r\n"
    for k, v in req['headers'].items():
        lines += f"{k}: {v}\r\n"
    lines += "\r\n"
    if req['body']:
        lines += req['body']
    return lines.encode('utf-8', errors='replace')


def save_to_django(req):
    try:
        if not setup_django():
            return
        from mon_projet.models import ProxyRequest
        host = req['host'].split(':')[0] if req['host'] else ''
        pr = ProxyRequest.objects.create(
            method=req['method'],
            url=f"http://{req['host']}{req['path']}",
            host=host,
            path=req['path'],
            request_headers=req['headers'],
            request_body=req['body'],
            intercepted=is_intercept_enabled(),
        )
        if req['id'] in pending_requests:
            pending_requests[req['id']]['django_id'] = pr.id
            save_pending()
        print(f"[Proxy] Sauvegarde OK: {req['method']} {req['host']}{req['path']} (Django ID: {pr.id})")
    except Exception as e:
        print(f"[Proxy] Django save error: {e}")


def forward_to_server(req):
    host_header = req['host']
    if ':' in host_header:
        host, port = host_header.rsplit(':', 1)
        port = int(port)
    else:
        host = host_header
        port = 80

    try:
        ip = socket.gethostbyname(host)
        print(f"[Proxy] Connexion vers {host} ({ip}):{port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect((ip, port))
        clean_request = rebuild_request(req)
        s.sendall(clean_request)
        response = b""
        s.settimeout(10)
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        s.close()
        print(f"[Proxy] Reponse: {len(response)} bytes")
        return response
    except socket.gaierror as e:
        print(f"[Proxy] DNS error {host}: {e}")
        return f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nDNS error: {e}".encode()
    except Exception as e:
        print(f"[Proxy] Forward error: {e}")
        return f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nErreur: {e}".encode()


def handle_client(conn, addr):
    try:
        data = b""
        conn.settimeout(10)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\r\n\r\n' in data:
                    break
        except socket.timeout:
            pass

        if not data:
            conn.close()
            return

        req = parse_request(data)
        if not req:
            conn.close()
            return

        if req['method'] == 'CONNECT':
            print(f"[Proxy] CONNECT ignore (HTTPS): {req['host']}")
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            conn.close()
            return

        print(f"[Proxy] {req['method']} {req['host']}{req['path']}")

        if is_intercept_enabled():
            req_id = req['id']
            event = threading.Event()
            pending_requests[req_id] = {'event': event, 'conn': conn, 'data': data, 'req': req}
            print(f"[Proxy] Requete bloquee: {req_id}")
            threading.Thread(target=save_to_django, args=(req,), daemon=True).start()

            action = None
            start = time.time()
            while time.time() - start < 60:
                if event.wait(timeout=0.5):
                    action = 'forward'
                    break
                signal = check_signal(req_id)
                if signal == 'forward':
                    action = 'forward'
                    break
                elif signal == 'drop':
                    action = 'drop'
                    break

            pending_requests.pop(req_id, None)
            save_pending()

            if action == 'drop' or action is None:
                print(f"[Proxy] Drop/Timeout: {req_id}")
                conn.close()
                return
            print(f"[Proxy] Forward OK: {req_id}")
        else:
            threading.Thread(target=save_to_django, args=(req,), daemon=True).start()

        response = forward_to_server(req)
        try:
            conn.sendall(response)
        except Exception as e:
            print(f"[Proxy] Send error: {e}")

    except Exception as e:
        print(f"[Proxy] Handler error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass


def forward_pending(req_id):
    entry = pending_requests.get(req_id)
    if entry:
        entry['event'].set()
        return True
    return False


def drop_pending(req_id):
    entry = pending_requests.pop(req_id, None)
    if entry:
        try:
            entry['conn'].close()
        except:
            pass
        save_pending()
        return True
    return False


def start_proxy():
    setup_django()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((PROXY_HOST, PROXY_PORT))
    except OSError as e:
        print(f"[Proxy] Erreur demarrage: {e}")
        return
    server.listen(100)
    print(f"[Proxy] Ecoute sur {PROXY_HOST}:{PROXY_PORT}")
    print(f"[Proxy] Configure Firefox : HTTP Proxy = 127.0.0.1:{PROXY_PORT}")
    print(f"[Proxy] Seul HTTP est supporte (pas HTTPS)")
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[Proxy] Arret.")
            break
        except Exception as e:
            print(f"[Proxy] Accept error: {e}")


if __name__ == '__main__':
    start_proxy()