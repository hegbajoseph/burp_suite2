"""
Scanner Engine - Détection de vulnérabilités web
Gère : XSS, SQLi, CSRF, Headers, IDOR, SSRF, Open Redirect, SSL
"""
import requests
import re
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
]

SQLI_PAYLOADS = [
    "'", "''", '"', "' OR '1'='1", "' OR 1=1 --",
    "1' ORDER BY 1--", "1' UNION SELECT NULL--", "'; DROP TABLE users--",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"MySQLSyntaxErrorException",
    r"ORA-[0-9]{4,5}:", r"Microsoft.*?ODBC.*?SQL Server",
    r"Incorrect syntax near", r"Unclosed quotation mark",
    r"SQLite.*?error", r"SQLITE_ERROR", r"PostgreSQL.*?ERROR",
    r"SQLSTATE\[", r"PDOException",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.0.1/", "file:///etc/passwd",
]

SSRF_PARAM_PATTERNS = re.compile(
    r'url|uri|path|src|source|dest|destination|redirect|fetch|load|request|proxy|target|endpoint|api',
    re.IGNORECASE
)

IDOR_PROBE_IDS = ['0', '1', '2', '9999', '00000000-0000-0000-0000-000000000001']

SECURITY_HEADERS = {
    'X-Frame-Options': {
        'severity': 'medium',
        'description': "X-Frame-Options manquant — vulnérable au Clickjacking.",
        'remediation': "Ajouter : X-Frame-Options: DENY",
    },
    'X-Content-Type-Options': {
        'severity': 'low',
        'description': "X-Content-Type-Options manquant.",
        'remediation': "Ajouter : X-Content-Type-Options: nosniff",
    },
    'Strict-Transport-Security': {
        'severity': 'medium',
        'description': "HSTS non activé — vulnérable au downgrade SSL.",
        'remediation': "Ajouter : Strict-Transport-Security: max-age=31536000",
    },
    'Content-Security-Policy': {
        'severity': 'medium',
        'description': "Aucune CSP définie — risque XSS élevé.",
        'remediation': "Définir une Content-Security-Policy stricte.",
    },
    'X-XSS-Protection': {
        'severity': 'low',
        'description': "X-XSS-Protection absent.",
        'remediation': "Ajouter : X-XSS-Protection: 1; mode=block",
    },
    'Referrer-Policy': {
        'severity': 'low',
        'description': "Referrer-Policy absente.",
        'remediation': "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
    },
}


def get_all_params(url, soup):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    params = {k: v[0] if v else '' for k, v in query_params.items()}
    forms = soup.find_all('form')
    form_data = []
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = {}
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                inputs[name] = inp.get('value', 'test')
        form_data.append({'action': action, 'method': method, 'inputs': inputs})
    return params, form_data


def inject_payload_in_url(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def make_request(url, method='GET', data=None, timeout=10, session=None):
    headers = {'User-Agent': 'Mozilla/5.0 (Security-Scanner/1.0)'}
    try:
        s = session or requests.Session()
        if method == 'POST':
            return s.post(url, data=data, headers=headers, timeout=timeout,
                          allow_redirects=False, verify=False)
        return s.get(url, headers=headers, timeout=timeout,
                     allow_redirects=True, verify=False)
    except requests.exceptions.RequestException as e:
        logger.warning(f"Erreur requête {url}: {e}")
        return None


def _extract_id_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    id_re = re.compile(r'\bid\b|_id$|^id_|uid|user|account|record|item', re.IGNORECASE)
    return {k: v[0] for k, v in params.items() if id_re.search(k) and v}
def scan_security_headers(url, response):
    issues = []
    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in resp_headers:
            issues.append({
                'issue_type': 'missing_header', 'severity': info['severity'],
                'title': f"En-tête manquant : {header}",
                'description': info['description'], 'url': url,
                'parameter': header, 'payload': '',
                'evidence': f"Headers reçus : {list(response.headers.keys())}",
                'remediation': info['remediation'],
            })
    return issues


def scan_ssl(url):
    issues = []
    if urlparse(url).scheme == 'http':
        issues.append({
            'issue_type': 'ssl', 'severity': 'high',
            'title': "Site servi en HTTP (non chiffré)",
            'description': "Communications en clair — risque MITM.",
            'url': url, 'parameter': '', 'payload': '',
            'evidence': "Schéma : http",
            'remediation': "Migrer vers HTTPS.",
        })
    return issues


def scan_csrf(url, soup):
    issues = []
    for form in soup.find_all('form'):
        if form.get('method', 'get').lower() != 'post':
            continue
        csrf_fields = form.find_all('input', attrs={
            'name': re.compile(r'csrf|token|_token|authenticity_token', re.IGNORECASE)
        })
        csrf_meta = soup.find('meta', attrs={'name': re.compile(r'csrf', re.IGNORECASE)})
        if not csrf_fields and not csrf_meta:
            action = form.get('action', url)
            issues.append({
                'issue_type': 'csrf', 'severity': 'medium',
                'title': "Formulaire POST sans protection CSRF",
                'description': f"Formulaire sur '{action}' sans token CSRF.",
                'url': urljoin(url, action) if action else url,
                'parameter': 'form', 'payload': '',
                'evidence': str(form)[:300],
                'remediation': "Ajouter un token CSRF dans chaque formulaire POST.",
            })
    return issues


def scan_xss(url, soup, session=None):
    issues = []
    params, forms = get_all_params(url, soup)
    for param in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_payload_in_url(url, param, payload)
            resp = make_request(test_url, session=session)
            if resp and payload in resp.text:
                issues.append({
                    'issue_type': 'xss', 'severity': 'high',
                    'title': f"XSS Réfléchi — paramètre '{param}'",
                    'description': f"'{param}' renvoie le payload sans encodage.",
                    'url': test_url, 'parameter': param, 'payload': payload,
                    'evidence': f"Payload '{payload}' retrouvé dans la réponse.",
                    'remediation': "Encoder toutes les sorties. Implémenter CSP.",
                })
                break
    for form in forms:
        if not form['inputs']:
            continue
        action_url = urljoin(url, form['action']) if form['action'] else url
        for field in form['inputs']:
            for payload in XSS_PAYLOADS[:3]:
                test_data = dict(form['inputs'])
                test_data[field] = payload
                resp = make_request(action_url, method='POST', data=test_data, session=session)
                if resp and payload in resp.text:
                    issues.append({
                        'issue_type': 'xss', 'severity': 'high',
                        'title': f"XSS POST — champ '{field}'",
                        'description': f"Champ '{field}' vulnérable au XSS.",
                        'url': action_url, 'parameter': field, 'payload': payload,
                        'evidence': "Payload retrouvé dans la réponse POST.",
                        'remediation': "Valider et encoder toutes les entrées.",
                    })
                    break
    return issues


def scan_sqli(url, soup, session=None):
    issues = []
    params, _ = get_all_params(url, soup)
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_url = inject_payload_in_url(url, param, payload)
            resp = make_request(test_url, session=session)
            if not resp:
                continue
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    issues.append({
                        'issue_type': 'sqli', 'severity': 'high',
                        'title': f"Injection SQL — paramètre '{param}'",
                        'description': f"'{param}' génère une erreur SQL.",
                        'url': test_url, 'parameter': param, 'payload': payload,
                        'evidence': f"Pattern détecté : {pattern}",
                        'remediation': "Utiliser des requêtes préparées.",
                    })
                    break
            else:
                continue
            break
    return issues


def scan_idor(url, soup, session=None):
    issues = []
    id_params = _extract_id_params(url)
    for param, original_value in id_params.items():
        ref_resp = make_request(url, session=session)
        if not ref_resp:
            continue
        ref_length = len(ref_resp.text)
        for probe_id in IDOR_PROBE_IDS:
            if probe_id == original_value:
                continue
            test_url = inject_payload_in_url(url, param, probe_id)
            resp = make_request(test_url, session=session)
            if not resp:
                continue
            if (resp.status_code == 200 and
                    abs(len(resp.text) - ref_length) < ref_length * 0.3 and
                    len(resp.text) > 100):
                issues.append({
                    'issue_type': 'idor', 'severity': 'high',
                    'title': f"IDOR potentiel — paramètre '{param}'",
                    'description': f"'{param}' accepte '{probe_id}' et retourne HTTP 200.",
                    'url': test_url, 'parameter': param, 'payload': probe_id,
                    'evidence': f"Original: '{original_value}' → {ref_length}B. Probe: '{probe_id}' → {len(resp.text)}B.",
                    'remediation': "Vérifier les autorisations côté serveur pour chaque ressource.",
                })
                break
    return issues


def scan_ssrf(url, soup, session=None):
    issues = []
    params, forms = get_all_params(url, soup)
    ssrf_params = [p for p in params if SSRF_PARAM_PATTERNS.search(p)]
    for param in ssrf_params:
        for payload in SSRF_PAYLOADS[:4]:
            test_url = inject_payload_in_url(url, param, payload)
            resp = make_request(test_url, session=session, timeout=5)
            if not resp:
                continue
            cloud_patterns = [r'ami-id', r'instance-id', r'root:.*:/bin/', r'computeMetadata']
            for pattern in cloud_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    issues.append({
                        'issue_type': 'ssrf', 'severity': 'high',
                        'title': f"SSRF confirmé — paramètre '{param}'",
                        'description': f"Le serveur a contacté '{payload}' via '{param}'.",
                        'url': test_url, 'parameter': param, 'payload': payload,
                        'evidence': f"Pattern détecté : {pattern}",
                        'remediation': "Bloquer les IPs internes. Utiliser une liste blanche d'URLs.",
                    })
                    break
    return issues


ALL_AREAS = ['headers', 'ssl', 'csrf', 'xss', 'sqli', 'idor', 'ssrf']


# ─── Ajouter ces fonctions juste avant la classe VulnerabilityScanner ────────
# Et modifier la classe comme indiqué ci-dessous
# ─────────────────────────────────────────────────────────────────────────────

# Profils d'authentification connus pour les apps de Metasploitable
AUTH_PROFILES = {
    'dvwa': {
        'login_url':    'http://{host}/dvwa/login.php',
        'credentials':  {'username': 'admin', 'password': 'password', 'Login': 'Login'},
        'success_text': 'Welcome',
        'cookie_name':  'PHPSESSID',
        'security_url': 'http://{host}/dvwa/security.php',
        'security_data': {'security': 'low', 'seclev_submit': 'Submit'},
    },
    'mutillidae': {
        'login_url':    'http://{host}/mutillidae/index.php?page=login.php',
        'credentials':  {
            'username':                  'admin',
            'password':                  'adminpass',
            'login-php-submit-button':   'Login',
        },
        'success_text': 'Logged In',
        'cookie_name':  'PHPSESSID',
    },
}


def detect_app(url):
    """Détecter l'application à partir de l'URL."""
    url_lower = url.lower()
    if 'dvwa' in url_lower:
        return 'dvwa'
    if 'mutillidae' in url_lower:
        return 'mutillidae'
    return None


def authenticate(session, url):
    """
    Tenter de s'authentifier automatiquement selon l'application détectée.
    Retourne True si l'authentification a réussi, False sinon.
    """
    host   = urlparse(url).netloc
    app    = detect_app(url)

    if not app or app not in AUTH_PROFILES:
        return False

    profile   = AUTH_PROFILES[app]
    login_url = profile['login_url'].format(host=host)

    try:
        # 1. Charger la page de login pour récupérer les tokens éventuels
        resp = session.get(login_url, timeout=10, verify=False)
        if not resp:
            return False

        # Extraire un token CSRF si présent dans la page de login
        soup        = BeautifulSoup(resp.text, 'html.parser')
        credentials = dict(profile['credentials'])

        # Chercher user_token (DVWA)
        token_input = soup.find('input', {'name': 'user_token'})
        if token_input:
            credentials['user_token'] = token_input.get('value', '')

        # 2. Soumettre le formulaire de login
        login_resp = session.post(
            login_url,
            data=credentials,
            timeout=10,
            verify=False,
            allow_redirects=True,
        )

        # 3. Vérifier le succès
        success = profile['success_text'].lower() in login_resp.text.lower()

        if success:
            # 4. Pour DVWA : mettre le niveau de sécurité sur 'low'
            if app == 'dvwa' and 'security_url' in profile:
                sec_url = profile['security_url'].format(host=host)
                # Récupérer le token pour la page sécurité
                sec_page = session.get(sec_url, timeout=10, verify=False)
                sec_soup = BeautifulSoup(sec_page.text, 'html.parser')
                sec_data = dict(profile['security_data'])
                sec_token = sec_soup.find('input', {'name': 'user_token'})
                if sec_token:
                    sec_data['user_token'] = sec_token.get('value', '')
                session.post(sec_url, data=sec_data, timeout=10, verify=False)

            print(f"[Scanner] Authentification réussie sur {app}")
            return True

        print(f"[Scanner] Authentification échouée sur {app} — texte attendu '{profile['success_text']}' non trouvé")
        return False

    except Exception as e:
        print(f"[Scanner] Erreur authentification : {e}")
        return False


# ─── Remplacer la classe VulnerabilityScanner par cette version ───────────────

class VulnerabilityScanner:
    def __init__(self, scan_id, progress_callback=None):
        self.scan_id           = scan_id
        self.progress_callback = progress_callback
        self.issues            = []
        self.session           = requests.Session()
        self.session.verify    = False
        self.authenticated     = False

    def update_progress(self, step, message):
        if self.progress_callback:
            self.progress_callback(self.scan_id, step, message)

    def scan(self, url, scan_type='full', scan_areas=None):
        self.issues = []

        if not scan_areas:
            active_areas = ALL_AREAS
        else:
            active_areas = [a for a in ALL_AREAS if a in scan_areas]

        if scan_type == 'passive':
            active_areas = [a for a in active_areas if a in ('headers', 'ssl', 'csrf')]

        results = {
            'scan_id':    str(self.scan_id),
            'url':        url,
            'status':     'running',
            'issues':     [],
            'summary':    {},
            'started_at': datetime.now().isoformat(),
        }

        try:
            # ── Étape 0 : Authentification automatique ────────────────────
            self.update_progress(3, "Tentative d'authentification...")
            self.authenticated = authenticate(self.session, url)
            if self.authenticated:
                self.update_progress(8, "Authentifié — démarrage du scan...")
            else:
                self.update_progress(8, "Non authentifié — scan sans session...")

            # ── Étape 1 : Connexion initiale ──────────────────────────────
            self.update_progress(10, "Connexion au site cible...")
            response = make_request(url, session=self.session)
            if not response:
                results['status'] = 'failed'
                results['error']  = "Impossible de contacter le site cible."
                return results

            soup  = BeautifulSoup(response.text, 'html.parser')
            total = len(active_areas)
            step  = 0

            # ── Headers ───────────────────────────────────────────────────
            if 'headers' in active_areas:
                step += 1
                self.update_progress(int(10 + (step/total)*80), "Analyse des en-têtes HTTP...")
                self.issues += scan_security_headers(url, response)

            # ── SSL ───────────────────────────────────────────────────────
            if 'ssl' in active_areas:
                step += 1
                self.update_progress(int(10 + (step/total)*80), "Vérification SSL/TLS...")
                self.issues += scan_ssl(url)

            # ── CSRF ──────────────────────────────────────────────────────
            if 'csrf' in active_areas:
                step += 1
                self.update_progress(int(10 + (step/total)*80), "Analyse CSRF...")
                self.issues += scan_csrf(url, soup)

            # ── XSS ───────────────────────────────────────────────────────
            if 'xss' in active_areas:
                step += 1
                self.update_progress(int(10 + (step/total)*80), "Test XSS...")
                self.issues += scan_xss(url, soup, session=self.session)

            # ── SQLi ──────────────────────────────────────────────────────
            if 'sqli' in active_areas:
                step += 1
                self.update_progress(int(10 + (step/total)*80), "Test SQLi...")
                self.issues += scan_sqli(url, soup, session=self.session)

            # ── IDOR ──────────────────────────────────────────────────────
            if 'idor' in active_areas:
                step += 1
                self.update_progress(int(10 + (step/total)*80), "Détection IDOR...")
                self.issues += scan_idor(url, soup, session=self.session)

            # ── SSRF ──────────────────────────────────────────────────────
            if 'ssrf' in active_areas:
                step += 1
                self.update_progress(int(10 + (step/total)*80), "Détection SSRF...")
                self.issues += scan_ssrf(url, soup, session=self.session)

            # ── Résumé ────────────────────────────────────────────────────
            summary = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for issue in self.issues:
                sev = issue.get('severity', 'info')
                summary[sev] = summary.get(sev, 0) + 1

            results['status']        = 'completed'
            results['issues']        = self.issues
            results['summary']       = summary
            results['total_issues']  = len(self.issues)
            results['completed_at']  = datetime.now().isoformat()
            results['authenticated'] = self.authenticated

            self.update_progress(100, f"Scan terminé — {len(self.issues)} vulnérabilité(s) trouvée(s).")

        except Exception as e:
            logger.error(f"Erreur scan {url}: {e}", exc_info=True)
            results['status'] = 'failed'
            results['error']  = str(e)

        return results