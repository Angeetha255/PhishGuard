"""
PhishGuard AI — Feature Extraction Engine
==========================================
Extracts 42 handcrafted features from a URL for phishing detection.
These features are used by the ML ensemble model AND the heuristic engine.
"""

import re
import math
import unicodedata
from urllib.parse import urlparse, unquote

# ── Constants ──────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link',
    '.online', '.site', '.info', '.biz', '.ru', '.cn', '.pw', '.cc',
    '.ws', '.su', '.icu', '.vip', '.win', '.bid', '.loan', '.party',
    '.review', '.trade', '.date', '.faith', '.racing', '.accountant',
    '.science', '.work', '.ninja', '.download', '.stream',
}

BRAND_NAMES = {
    'paypal', 'google', 'facebook', 'apple', 'microsoft', 'amazon',
    'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays',
    'dropbox', 'yahoo', 'outlook', 'office365', 'onedrive', 'icloud',
    'whatsapp', 'telegram', 'snapchat', 'tiktok', 'spotify', 'adobe',
    'docusign', 'fedex', 'dhl', 'ups', 'usps', 'irs', 'gov',
}

PHISHING_KEYWORDS = {
    'login', 'signin', 'sign-in', 'logon', 'log-in',
    'verify', 'verification', 'validate', 'validation',
    'secure', 'security', 'safety',
    'account', 'accounts', 'myaccount',
    'update', 'confirm', 'confirmation',
    'banking', 'bank', 'payment', 'pay', 'billing', 'invoice',
    'password', 'passwd', 'credential', 'credentials',
    'support', 'helpdesk', 'help-desk', 'customer-service',
    'suspended', 'unusual', 'activity', 'unauthorized',
    'click', 'free', 'prize', 'winner', 'lucky', 'gift', 'offer',
    'urgent', 'alert', 'warning', 'limited', 'expire', 'expired',
    'reset', 'recover', 'recovery', 'restore',
    'webscr', 'token', 'auth', 'oauth', 'session',
    'redirect', 'forward', 'continue',
    'submit', 'form', 'input',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae',
    'po.st', 'bc.vc', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us',
    'u.bb', 'yourls.org', 'x.co', 'prettylinkpro.com', 'viralurl.com',
    'cli.gs', 'ff.im', 'smallr.com', 'twurl.nl', 'snipurl.com',
    'short.to', 'budurl.com', 'ping.fm', 'post.ly', 'just.as',
    'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com',
    'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly',
    'bit.do', 'rb.gy', 'cutt.ly', 'shorturl.at', 'tinyurl.com',
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _get_registered_domain(netloc: str) -> str:
    """Return the last two labels of a hostname (registered domain)."""
    parts = netloc.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else netloc


def _is_ip(netloc: str) -> bool:
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$', netloc))


def _is_punycode(netloc: str) -> bool:
    return 'xn--' in netloc.lower()


def _has_homograph(netloc: str) -> bool:
    """Detect non-ASCII characters that visually resemble ASCII (homograph attack)."""
    try:
        netloc.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True


def _looks_random(s: str, threshold: float = 3.8) -> bool:
    """High entropy + long string = likely randomly generated domain."""
    return len(s) > 8 and _entropy(s) > threshold


# ── Main Feature Extractor ─────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract 42 phishing-detection features from a URL.
    Returns an ordered dict; call list(result.values()) for a numeric vector.
    """
    url = url.strip()
    url_lower = url.lower()

    try:
        parsed = urlparse(url)
    except Exception:
        return {k: 0 for k in _feature_names()}

    netloc   = parsed.netloc.lower()
    path     = parsed.path.lower()
    query    = parsed.query.lower()
    fragment = parsed.fragment.lower()
    full     = url_lower

    # Strip port from netloc for domain analysis
    hostname = netloc.split(':')[0]
    reg_domain = _get_registered_domain(hostname)

    # ── 1. Length features ─────────────────────────────────
    f = {}
    f['url_length']        = len(url)
    f['domain_length']     = len(hostname)
    f['path_length']       = len(path)
    f['query_length']      = len(query)

    # ── 2. Count features ──────────────────────────────────
    f['num_dots']          = url.count('.')
    f['num_hyphens']       = url.count('-')
    f['num_underscores']   = url.count('_')
    f['num_slashes']       = url.count('/')
    f['num_question_marks']= url.count('?')
    f['num_equals']        = url.count('=')
    f['num_ampersands']    = url.count('&')
    f['num_at_signs']      = url.count('@')
    f['num_percent']       = url.count('%')
    f['num_digits_in_url'] = sum(c.isdigit() for c in url)
    f['num_subdomains']    = max(0, hostname.count('.') - 1)

    # ── 3. Protocol / structure ────────────────────────────
    f['is_https']          = 1 if url.startswith('https://') else 0
    f['is_http']           = 1 if url.startswith('http://') else 0
    f['has_at_in_url']     = 1 if '@' in url else 0
    f['has_double_slash']  = 1 if '//' in url[8:] else 0
    f['has_encoded_chars'] = 1 if '%' in url else 0
    f['is_ip_address']     = 1 if _is_ip(hostname) else 0
    f['is_url_shortener']  = 1 if any(hostname == s or hostname.endswith('.' + s)
                                      for s in URL_SHORTENERS) else 0

    # ── 4. Domain-level signals ────────────────────────────
    f['domain_hyphen_count']  = hostname.count('-')
    f['domain_digit_count']   = sum(c.isdigit() for c in hostname)
    f['domain_entropy']       = round(_entropy(hostname), 4)
    f['is_punycode']          = 1 if _is_punycode(hostname) else 0
    f['has_homograph']        = 1 if _has_homograph(hostname) else 0
    f['looks_random_domain']  = 1 if _looks_random(reg_domain.split('.')[0]) else 0

    # ── 5. TLD signals ─────────────────────────────────────
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    f['suspicious_tld']    = 1 if tld in SUSPICIOUS_TLDS else 0

    # ── 6. Brand impersonation ─────────────────────────────
    brand_in_url   = any(b in full for b in BRAND_NAMES)
    brand_in_reg   = any(b in reg_domain for b in BRAND_NAMES)
    # Brand appears in URL but NOT in the registered domain → spoofing
    f['brand_in_subdomain_or_path'] = 1 if (brand_in_url and not brand_in_reg) else 0
    f['brand_in_registered_domain'] = 1 if brand_in_reg else 0

    # ── 7. Keyword signals ─────────────────────────────────
    kw_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in full)
    f['phishing_keyword_count'] = kw_hits
    f['has_login_keyword']      = 1 if any(k in full for k in ('login','signin','logon','log-in','sign-in')) else 0
    f['has_verify_keyword']     = 1 if any(k in full for k in ('verify','verification','validate')) else 0
    f['has_secure_keyword']     = 1 if 'secure' in full or 'security' in full else 0
    f['has_account_keyword']    = 1 if 'account' in full else 0
    f['has_update_keyword']     = 1 if any(k in full for k in ('update','confirm','reset','recover')) else 0

    # ── 8. Entropy / randomness ────────────────────────────
    f['url_entropy']       = round(_entropy(url), 4)
    f['path_entropy']      = round(_entropy(path), 4)

    # ── 9. Structural red flags ────────────────────────────
    f['path_depth']        = len([p for p in path.split('/') if p])
    f['query_param_count'] = len([p for p in query.split('&') if p]) if query else 0

    assert len(f) == 41, f"Expected 41 features, got {len(f)}"
    return f


def extract_feature_vector(url: str) -> list:
    """Return features as a plain 41-element list (for ML model input).
    Callers that need the 42nd heuristic_risk_score feature should append it:
        vec = extract_feature_vector(url)
        vec.append(run_rules(url)['rule_score'])
    """
    return list(extract_features(url).values())


def _feature_names() -> list:
    """Return the ordered list of 41 feature names (matches extract_features keys).
    The 42nd feature 'heuristic_risk_score' is appended externally by callers.
    """
    return [
        'url_length', 'domain_length', 'path_length', 'query_length',
        'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
        'num_question_marks', 'num_equals', 'num_ampersands', 'num_at_signs',
        'num_percent', 'num_digits_in_url', 'num_subdomains',
        'is_https', 'is_http', 'has_at_in_url', 'has_double_slash',
        'has_encoded_chars', 'is_ip_address', 'is_url_shortener',
        'domain_hyphen_count', 'domain_digit_count', 'domain_entropy',
        'is_punycode', 'has_homograph', 'looks_random_domain',
        'suspicious_tld',
        'brand_in_subdomain_or_path', 'brand_in_registered_domain',
        'phishing_keyword_count', 'has_login_keyword', 'has_verify_keyword',
        'has_secure_keyword', 'has_account_keyword', 'has_update_keyword',
        'url_entropy', 'path_entropy',
        'path_depth', 'query_param_count',
    ]


def get_feature_names() -> list:
    """Returns 41 base feature names. Append 'heuristic_risk_score' for 42."""
    return _feature_names()
