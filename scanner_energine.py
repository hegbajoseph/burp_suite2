"""
Scanner Engine - Détection de vulnérabilités web
Gère : XSS, SQLi, CSRF, Headers, IDOR, SSRF, Open Redirect, SSL
"""

import requests
import re
import time
import threading
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# ─── Payloads ────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '"><img src=x onerror=alert(1)>',
    '<body onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    ",",
    '"',
    '""',
    "/",
    "//",
    "\\",
    "\\\\",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "1=1",
    "1=2",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"Warning.*?mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    r"Unknown column '[^']+' in 'field list'",
    r"ORA-[0-9]{4,5}:",
    r"Oracle.*?Driver",
    r"Warning.*?oci_",
    r"Microsoft.*?ODBC.*?SQL Server",
    r"Incorrect syntax near",
    r"Unclosed quotation mark",
    r"SQLite.*?error",
    r"SQLITE_ERROR",
    r"PostgreSQL.*?ERROR",
    r"pg_query\(\)",
    r"ERROR.*?syntax error at or near",
    r"DB2.*?SQL.*?error",
    r"SQLSTATE\[",
    r"PDOException",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
]

# Payloads SSRF — tente de faire contacter des ressources internes par le serveur
SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",             # GCP metadata
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://[::1]/",                                # IPv6 localhost
    "file:///etc/passwd",
    "dict://localhost:11211/",
]

SSRF_PARAM_PATTERNS = re.compile(
    r'url|uri|path|src|source|dest|destination|redirect|fetch|load|request|proxy|target|endpoint|api',
    re.IGNORECASE
)

# Payloads IDOR — teste des IDs numériques et UUIDs communs autour de la valeur actuelle
IDOR_PROBE_IDS = ['0', '1', '2', '9999', '00000000-0000-0000-0000-000000000001']

SECURITY_HEADERS = {
    'X-Frame-Options': {
        'severity': 'medium',
        'description': "L'en-tête X-Frame-Options est manquant, rendant le site vulnérable au Clickjacking.",
        'remediation': "Ajouter l'en-tête : X-Frame-Options: DENY ou SAMEORIGIN",
    },
    'X-Content-Type-Options': {
        'severity': 'low',
        'description': "L'en-tête X-Content-Type-Options est manquant.",
        'remediation': "Ajouter l'en-tête : X-Content-Type-Options: nosniff",
    },
    'Strict-Transport-Security': {
        'severity': 'medium',
        'description': "HSTS n'est pas activé. Le site est vulnérable aux attaques de downgrade SSL.",
        'remediation': "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    'Content-Security-Policy': {
        'severity': 'medium',
        'description': "Aucune politique CSP définie. Risque élevé de XSS.",
        'remediation': "Définir une Content-Security-Policy stricte.",
    },
    'X-XSS-Protection': {
        'severity': 'low',
        'description': "L'en-tête X-XSS-Protection est absent.",
        'remediation': "Ajouter : X-XSS-Protection: 1; mode=block",
    },
    'Referrer-Policy': {
        'severity': 'low',
        'description': "Aucune Referrer-Policy définie. Des informations sensibles peuvent fuiter.",
        'remediation': "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
    },
}


# ─── Utilitaires ─────────────────────────────────────────────────────────────

def get_all_params(url, soup):
    """Extraire tous les paramètres GET et POST d'une page."""
    parsed      = urlparse(url)
    query_params = parse_qs(parsed.query)
    params      = {k: v[0] if v else '' for k, v in query_params.items()}

    forms = soup.find_all('form')
    form_data = []
    for form in forms:
        action  = form.get('action', '')
        method  = form.get('method', 'get').lower()
        inputs  = {}
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                inputs[name] = inp.get('value', 'test')
        form_data.append({'action': action, 'method': method, 'inputs': inputs})

    return params, form_data


def inject_payload_in_url(url, param, payload):
    """Injecter un payload dans un paramètre d'URL."""
    parsed    = urlparse(url)
    query     = parse_qs(parsed.query)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def make_request(url, method='GET', data=None, timeout=10, session=None):
    """Faire une requête HTTP avec gestion d'erreurs."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Security-Scanner/1.0)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }
    try:
        s = session or requests.Session()
        if method == 'POST':
            resp = s.post(url, data=data, headers=headers, timeout=timeout,
                          allow_redirects=False, verify=False)
        else:
            resp = s.get(url, headers=headers, timeout=timeout,
                         allow_redirects=True, verify=False)
        return resp
    except requests.exceptions.RequestException as e:
        logger.warning(f"Erreur requête {url}: {e}")
        return None


def _extract_id_params(url):
    """Retourner les paramètres qui ressemblent à des identifiants (id, user_id, etc.)."""
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)
    id_re   = re.compile(r'\bid\b|_id$|^id_|uid|user|account|record|item|object|doc|file', re.IGNORECASE)
    return {k: v[0] for k, v in params.items() if id_re.search(k) and v}


# ─── Modules de scan ─────────────────────────────────────────────────────────

def scan_security_headers(url, response):
    """Vérifier les en-têtes de sécurité HTTP."""
    issues       = []
    resp_headers = {k.lower(): v for k, v in response.headers.items()}

    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in resp_headers:
            issues.append({
                'issue_type':  'missing_header',
                'severity':    info['severity'],
                'title':       f"En-tête manquant : {header}",
                'description': info['description'],
                'url':         url,
                'parameter':   header,
                'payload':     '',
                'evidence':    f"Headers reçus : {list(response.headers.keys())}",
                'remediation': info['remediation'],
            })
    return issues


def scan_ssl(url):
    """Vérifier les problèmes SSL basiques."""
    issues = []
    if urlparse(url).scheme == 'http':
        issues.append({
            'issue_type':  'ssl',
            'severity':    'high',
            'title':       "Site servi en HTTP (non chiffré)",
            'description': "Le site utilise HTTP. Toutes les communications sont en clair.",
            'url':         url,
            'parameter':   '',
            'payload':     '',
            'evidence':    f"Schéma : http",
            'remediation': "Migrer vers HTTPS avec un certificat TLS valide.",
        })
    return issues


def scan_csrf(url, soup):
    """Vérifier la protection CSRF sur les formulaires POST."""
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
                'issue_type':  'csrf',
                'severity':    'medium',
                'title':       "Formulaire POST sans protection CSRF",
                'description': f"Le formulaire POST sur '{action}' n'a pas de token CSRF.",
                'url':         urljoin(url, action) if action else url,
                'parameter':   'form',
                'payload':     '',
                'evidence':    str(form)[:300],
                'remediation': "Ajouter un token CSRF unique par session dans chaque formulaire POST.",
            })
    return issues


def scan_xss(url, soup, session=None):
    """Tester XSS sur les paramètres GET et les formulaires POST."""
    issues = []
    params, forms = get_all_params(url, soup)

    # GET params
    for param in params:
        for payload in XSS_PAYLOADS[:5]:
            test_url = inject_payload_in_url(url, param, payload)
            resp     = make_request(test_url, session=session)
            if resp and payload in resp.text:
                issues.append({
                    'issue_type':  'xss',
                    'severity':    'high',
                    'title':       f"XSS Réfléchi — paramètre '{param}'",
                    'description': f"Le paramètre '{param}' renvoie le payload sans encodage.",
                    'url':         test_url,
                    'parameter':   param,
                    'payload':     payload,
                    'evidence':    f"Payload '{payload}' retrouvé dans la réponse.",
                    'remediation': "Encoder toutes les sorties. Implémenter une CSP stricte.",
                })
                break

    # Formulaires POST
    for form in forms:
        if not form['inputs']:
            continue
        action_url = urljoin(url, form['action']) if form['action'] else url
        for field in form['inputs']:
            for payload in XSS_PAYLOADS[:3]:
                test_data        = dict(form['inputs'])
                test_data[field] = payload
                resp             = make_request(action_url, method='POST', data=test_data, session=session)
                if resp and payload in resp.text:
                    issues.append({
                        'issue_type':  'xss',
                        'severity':    'high',
                        'title':       f"XSS POST — champ '{field}'",
                        'description': f"Le champ '{field}' est vulnérable au XSS.",
                        'url':         action_url,
                        'parameter':   field,
                        'payload':     payload,
                        'evidence':    "Payload retrouvé dans la réponse POST.",
                        'remediation': "Valider et encoder toutes les entrées de formulaire.",
                    })
                    break
    return issues


def scan_sqli(url, soup, session=None):
    """Tester les injections SQL sur les paramètres GET."""
    issues = []
    params, _ = get_all_params(url, soup)

    for param in params:
        for payload in SQLI_PAYLOADS[:8]:
            test_url = inject_payload_in_url(url, param, payload)
            resp     = make_request(test_url, session=session)
            if not resp:
                continue
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    issues.append({
                        'issue_type':  'sqli',
                        'severity':    'high',
                        'title':       f"Injection SQL — paramètre '{param}'",
                        'description': f"Le paramètre '{param}' génère une erreur SQL avec le payload.",
                        'url':         test_url,
                        'parameter':   param,
                        'payload':     payload,
                        'evidence':    f"Pattern détecté : {pattern}",
                        'remediation': "Utiliser des requêtes préparées (prepared statements).",
                    })
                    break
            else:
                continue
            break
    return issues


def scan_open_redirect(url, soup, session=None):
    """Détecter les redirections ouvertes."""
    issues = []
    params, _ = get_all_params(url, soup)
    redirect_params = [p for p in params if re.search(
        r'redirect|return|next|url|goto|dest|destination|forward|location', p, re.IGNORECASE
    )]
    for param in redirect_params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = inject_payload_in_url(url, param, payload)
            resp     = make_request(test_url, session=session)
            if resp and resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')
                if 'evil.com' in location or payload in location:
                    issues.append({
                        'issue_type':  'open_redirect',
                        'severity':    'medium',
                        'title':       f"Redirection ouverte — paramètre '{param}'",
                        'description': f"'{param}' redirige vers un domaine externe arbitraire.",
                        'url':         test_url,
                        'parameter':   param,
                        'payload':     payload,
                        'evidence':    f"Location: {location}",
                        'remediation': "Valider les URLs contre une liste blanche de domaines.",
                    })
                    break
    return issues


def scan_idor(url, soup, session=None):
    """
    Détecter les IDOR (Insecure Direct Object Reference).
    Stratégie : pour chaque paramètre ressemblant à un ID, tester d'autres valeurs
    et comparer le code HTTP et la taille de la réponse.
    """
    issues   = []
    id_params = _extract_id_params(url)

    for param, original_value in id_params.items():
        # Réponse de référence avec la valeur originale
        ref_resp = make_request(url, session=session)
        if not ref_resp:
            continue
        ref_status = ref_resp.status_code
        ref_length = len(ref_resp.text)

        for probe_id in IDOR_PROBE_IDS:
            if probe_id == original_value:
                continue
            test_url = inject_payload_in_url(url, param, probe_id)
            resp     = make_request(test_url, session=session)
            if not resp:
                continue

            # Suspect si : 200 OK avec une taille similaire à la référence (contenu renvoyé)
            same_status  = resp.status_code == 200 and ref_status == 200
            similar_size = abs(len(resp.text) - ref_length) < ref_length * 0.3  # ±30%
            not_empty    = len(resp.text) > 100

            if same_status and similar_size and not_empty and probe_id != original_value:
                issues.append({
                    'issue_type':  'idor',
                    'severity':    'high',
                    'title':       f"IDOR potentiel — paramètre '{param}'",
                    'description': (
                        f"Le paramètre '{param}' accepte la valeur '{probe_id}' (différente de "
                        f"'{original_value}') et retourne une réponse HTTP 200 avec un contenu similaire. "
                        f"Cela peut indiquer un accès non autorisé à des ressources d'autres utilisateurs."
                    ),
                    'url':         test_url,
                    'parameter':   param,
                    'payload':     probe_id,
                    'evidence':    (
                        f"Valeur originale : '{original_value}' → Status {ref_status}, {ref_length} octets. "
                        f"Valeur testée : '{probe_id}' → Status {resp.status_code}, {len(resp.text)} octets."
                    ),
                    'remediation': (
                        "Vérifier les autorisations côté serveur pour chaque accès à une ressource. "
                        "Ne pas se fier uniquement à l'ID fourni par le client. "
                        "Implémenter un contrôle d'accès basé sur la session utilisateur."
                    ),
                })
                break  # Un seul issue par paramètre
    return issues


def scan_ssrf(url, soup, session=None):
    """
    Détecter les SSRF (Server-Side Request Forgery).
    Stratégie : injecter des URLs internes dans les paramètres suspects,
    et analyser les réponses (timeout différent, contenu inattendu, code HTTP).
    """
    issues  = []
    params, forms = get_all_params(url, soup)

    # Filtrer les paramètres suspects (url, src, dest, api, etc.)
    ssrf_params = [p for p in params if SSRF_PARAM_PATTERNS.search(p)]

    # Aussi tester les champs de formulaire avec des noms suspects
    ssrf_form_fields = []
    for form in forms:
        for field_name in form['inputs']:
            if SSRF_PARAM_PATTERNS.search(field_name):
                ssrf_form_fields.append((form, field_name))

    for param in ssrf_params:
        for payload in SSRF_PAYLOADS[:5]:
            test_url = inject_payload_in_url(url, param, payload)
            t_start  = time.time()
            resp     = make_request(test_url, session=session, timeout=5)
            elapsed  = time.time() - t_start

            if resp is None:
                # Timeout ou connexion refusée — peut indiquer une tentative SSRF bloquée
                continue

            # Heuristiques de détection SSRF :
            # 1. Réponse contient du contenu typique des metadata cloud
            cloud_patterns = [
                r'ami-id', r'instance-id', r'local-ipv4',   # AWS
                r'computeMetadata',                           # GCP
                r'root:.*:/bin/',                             # /etc/passwd
            ]
            for pattern in cloud_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    issues.append({
                        'issue_type':  'ssrf',
                        'severity':    'high',
                        'title':       f"SSRF confirmé — paramètre '{param}'",
                        'description': (
                            f"Le serveur a contacté '{payload}' via le paramètre '{param}' "
                            f"et la réponse contient des données internes."
                        ),
                        'url':         test_url,
                        'parameter':   param,
                        'payload':     payload,
                        'evidence':    f"Pattern détecté dans la réponse : {pattern}",
                        'remediation': (
                            "Valider et filtrer toutes les URLs fournies par l'utilisateur. "
                            "Bloquer les requêtes vers les plages IP internes (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16). "
                            "Utiliser une liste blanche de domaines autorisés."
                        ),
                    })
                    break

            # 2. Réponse HTTP 200 sur un payload local → suspect
            if resp.status_code == 200 and ('127.0.0.1' in payload or 'localhost' in payload):
                # Éviter les faux positifs : vérifier que ce n'est pas la page normale
                normal_resp = make_request(url, session=session)
                if normal_resp and abs(len(resp.text) - len(normal_resp.text)) > 200:
                    issues.append({
                        'issue_type':  'ssrf',
                        'severity':    'high',
                        'title':       f"SSRF potentiel — paramètre '{param}'",
                        'description': (
                            f"Le paramètre '{param}' avec la valeur '{payload}' retourne "
                            f"HTTP 200 avec un contenu différent de la page normale."
                        ),
                        'url':         test_url,
                        'parameter':   param,
                        'payload':     payload,
                        'evidence':    (
                            f"Réponse normale : {len(normal_resp.text)} octets. "
                            f"Réponse avec payload : {len(resp.text)} octets."
                        ),
                        'remediation': (
                            "Bloquer les requêtes vers localhost et les IPs internes. "
                            "Implémenter une liste blanche d'URLs autorisées."
                        ),
                    })

    # Tester aussi les formulaires
    for form, field_name in ssrf_form_fields[:3]:  # Limiter à 3 formulaires
        action_url = urljoin(url, form['action']) if form['action'] else url
        for payload in SSRF_PAYLOADS[:3]:
            test_data             = dict(form['inputs'])
            test_data[field_name] = payload
            resp                  = make_request(action_url, method='POST', data=test_data, session=session, timeout=5)
            if resp and resp.status_code == 200:
                for pattern in [r'root:.*:/bin/', r'ami-id', r'instance-id']:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        issues.append({
                            'issue_type':  'ssrf',
                            'severity':    'high',
                            'title':       f"SSRF via formulaire — champ '{field_name}'",
                            'description': f"Le champ '{field_name}' permet une SSRF via POST.",
                            'url':         action_url,
                            'parameter':   field_name,
                            'payload':     payload,
                            'evidence':    f"Pattern '{pattern}' trouvé dans la réponse POST.",
                            'remediation': "Valider et filtrer toutes les URLs soumises par formulaire.",
                        })
                        break
    return issues


# ─── Moteur principal ─────────────────────────────────────────────────────────

# Mapping nom de zone → fonction de scan
SCAN_MODULES = {
    'headers': scan_security_headers,   # appelé différemment (besoin de response)
    'ssl':     scan_ssl,
    'csrf':    scan_csrf,
    'xss':     scan_xss,
    'sqli':    scan_sqli,
    'idor':    scan_idor,
    'ssrf':    scan_ssrf,
}

# Toutes les zones disponibles (ordre d'exécution)
ALL_AREAS = ['headers', 'ssl', 'csrf', 'xss', 'sqli', 'idor', 'ssrf']


class VulnerabilityScanner:
    def __init__(self, scan_id, progress_callback=None):
        self.scan_id           = scan_id
        self.progress_callback = progress_callback
        self.issues            = []
        self.session           = requests.Session()
        self.session.verify    = False

    def update_progress(self, step, message):
        if self.progress_callback:
            self.progress_callback(self.scan_id, step, message)

    def scan(self, url, scan_type='full', scan_areas=None):
        """
        Lancer le scan.

        scan_type  : 'full' | 'passive' | 'active'
            - passive : headers + ssl + csrf seulement (pas de payloads actifs)
            - active  : tous les modules
            - full    : identique à active

        scan_areas : liste de zones à activer, ex. ['sqli', 'xss', 'headers']
                     None = toutes les zones
        """
        self.issues = []

        # Déterminer les zones actives
        if scan_areas is None or len(scan_areas) == 0:
            active_areas = ALL_AREAS
        else:
            active_areas = [a for a in ALL_AREAS if a in scan_areas]

        # Mode passif : restreindre aux modules non-intrusifs
        if scan_type == 'passive':
            active_areas = [a for a in active_areas if a in ('headers', 'ssl', 'csrf')]

        results = {
            'scan_id':    str(self.scan_id),
            'url':        url,
            'status':     'running',
            'issues':     [],
            'summary':    {},
            'started_at': datetime.now().isoformat(),
            'scan_type':  scan_type,
            'areas':      active_areas,
        }

        try:
            # ── Étape 0 : connexion initiale ──────────────────────────────
            self.update_progress(5, "Connexion au site cible...")
            response = make_request(url, session=self.session)
            if not response:
                results['status'] = 'failed'
                results['error']  = "Impossible de contacter le site cible."
                return results

            soup = BeautifulSoup(response.text, 'html.parser')

            total  = len(active_areas)
            step   = 0

            # ── Étape 1 : Headers ─────────────────────────────────────────
            if 'headers' in active_areas:
                step += 1
                pct = int(5 + (step / total) * 85)
                self.update_progress(pct, "Analyse des en-têtes HTTP...")
                self.issues += scan_security_headers(url, response)

            # ── Étape 2 : SSL ─────────────────────────────────────────────
            if 'ssl' in active_areas:
                step += 1
                pct = int(5 + (step / total) * 85)
                self.update_progress(pct, "Vérification SSL/TLS...")
                self.issues += scan_ssl(url)

            # ── Étape 3 : CSRF ────────────────────────────────────────────
            if 'csrf' in active_areas:
                step += 1
                pct = int(5 + (step / total) * 85)
                self.update_progress(pct, "Analyse CSRF des formulaires...")
                self.issues += scan_csrf(url, soup)

            # ── Étape 4 : XSS ─────────────────────────────────────────────
            if 'xss' in active_areas:
                step += 1
                pct = int(5 + (step / total) * 85)
                self.update_progress(pct, "Test des injections XSS...")
                self.issues += scan_xss(url, soup, session=self.session)

            # ── Étape 5 : SQLi ────────────────────────────────────────────
            if 'sqli' in active_areas:
                step += 1
                pct = int(5 + (step / total) * 85)
                self.update_progress(pct, "Test des injections SQL...")
                self.issues += scan_sqli(url, soup, session=self.session)

            # ── Étape 6 : IDOR ────────────────────────────────────────────
            if 'idor' in active_areas:
                step += 1
                pct = int(5 + (step / total) * 85)
                self.update_progress(pct, "Détection IDOR...")
                self.issues += scan_idor(url, soup, session=self.session)

            # ── Étape 7 : SSRF ────────────────────────────────────────────
            if 'ssrf' in active_areas:
                step += 1
                pct = int(5 + (step / total) * 85)
                self.update_progress(pct, "Détection SSRF...")
                self.issues += scan_ssrf(url, soup, session=self.session)

            # ── Résumé ────────────────────────────────────────────────────
            summary = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for issue in self.issues:
                sev = issue.get('severity', 'info')
                summary[sev] = summary.get(sev, 0) + 1

            results['status']       = 'completed'
            results['issues']       = self.issues
            results['summary']      = summary
            results['total_issues'] = len(self.issues)
            results['completed_at'] = datetime.now().isoformat()

            self.update_progress(100, f"Scan terminé — {len(self.issues)} vulnérabilité(s) trouvée(s).")

        except Exception as e:
            logger.error(f"Erreur scan {url}: {e}", exc_info=True)
            results['status'] = 'failed'
            results['error']  = str(e)

        return results