"""
PhishGuard AI — Phishing Rules Engine
======================================
A deterministic, rule-based layer that runs BEFORE the ML model.
Rules are ordered by severity. A hard-block rule immediately returns
phishing=True with a high confidence score.

Design goals:
  - Zero false negatives on obvious phishing patterns
  - Each rule returns a (triggered: bool, score_boost: float, reason: str)
  - Final score = base_score + sum(boosts), clamped to [0, 1]
"""

import re
from urllib.parse import urlparse
from utils.feature_extraction import (
    SUSPICIOUS_TLDS, BRAND_NAMES, PHISHING_KEYWORDS, URL_SHORTENERS,
    _is_ip, _is_punycode, _has_homograph, _looks_random,
    _get_registered_domain, _entropy,
)

# ── Rule result dataclass ──────────────────────────────────────────────────────

class RuleResult:
    def __init__(self, triggered: bool, score: float, reason: str, hard_block: bool = False):
        self.triggered  = triggered
        self.score      = score       # 0.0 – 1.0 contribution
        self.reason     = reason
        self.hard_block = hard_block  # if True, skip ML and return phishing immediately


# ── Individual rules ───────────────────────────────────────────────────────────

def rule_ip_address(url, parsed, hostname, reg_domain, full):
    """URLs using raw IP addresses instead of domain names."""
    if _is_ip(hostname):
        return RuleResult(True, 0.85, "IP address used as host", hard_block=True)
    return RuleResult(False, 0.0, "")


def rule_at_sign(url, parsed, hostname, reg_domain, full):
    """@ in URL redirects browser to ignore everything before it."""
    if '@' in url:
        return RuleResult(True, 0.80, "@ symbol in URL (redirect trick)", hard_block=True)
    return RuleResult(False, 0.0, "")


def rule_brand_impersonation(url, parsed, hostname, reg_domain, full):
    """Brand name in subdomain/path but NOT in registered domain."""
    for brand in BRAND_NAMES:
        if brand in full and brand not in reg_domain:
            return RuleResult(True, 0.75,
                f"Brand '{brand}' impersonated in URL (not in registered domain)",
                hard_block=True)
    return RuleResult(False, 0.0, "")


def rule_suspicious_tld_plus_keyword(url, parsed, hostname, reg_domain, full):
    """Suspicious TLD combined with any phishing keyword — very high signal."""
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    has_sus_tld = tld in SUSPICIOUS_TLDS
    kw_hits = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if has_sus_tld and kw_hits:
        return RuleResult(True, 0.80,
            f"Suspicious TLD '{tld}' + phishing keywords {kw_hits[:3]}",
            hard_block=True)
    return RuleResult(False, 0.0, "")


def rule_punycode_homograph(url, parsed, hostname, reg_domain, full):
    """Punycode or homograph characters used to spoof legitimate domains."""
    if _is_punycode(hostname):
        return RuleResult(True, 0.75, "Punycode domain (possible homograph attack)", hard_block=True)
    if _has_homograph(hostname):
        return RuleResult(True, 0.75, "Non-ASCII characters in domain (homograph attack)", hard_block=True)
    return RuleResult(False, 0.0, "")


def rule_double_slash_redirect(url, parsed, hostname, reg_domain, full):
    """Double slash after protocol used for open redirect."""
    if '//' in url[8:]:
        return RuleResult(True, 0.65, "Double slash redirect in URL path", hard_block=False)
    return RuleResult(False, 0.0, "")


def rule_suspicious_tld_only(url, parsed, hostname, reg_domain, full):
    """Suspicious TLD alone (without keyword) — medium signal."""
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    if tld in SUSPICIOUS_TLDS:
        return RuleResult(True, 0.35, f"Suspicious TLD: {tld}")
    return RuleResult(False, 0.0, "")


def rule_excessive_hyphens(url, parsed, hostname, reg_domain, full):
    """Many hyphens in domain — common in phishing (paypal-secure-login.com)."""
    count = hostname.count('-')
    if count >= 4:
        return RuleResult(True, 0.55, f"{count} hyphens in domain")
    if count >= 2:
        return RuleResult(True, 0.30, f"{count} hyphens in domain")
    return RuleResult(False, 0.0, "")


def rule_long_url(url, parsed, hostname, reg_domain, full):
    """Unusually long URLs are a phishing indicator."""
    if len(url) > 200:
        return RuleResult(True, 0.40, f"Very long URL ({len(url)} chars)")
    if len(url) > 120:
        return RuleResult(True, 0.20, f"Long URL ({len(url)} chars)")
    return RuleResult(False, 0.0, "")


def rule_many_subdomains(url, parsed, hostname, reg_domain, full):
    """Excessive subdomains used to bury the real domain."""
    depth = hostname.count('.')
    if depth >= 4:
        return RuleResult(True, 0.50, f"Excessive subdomains (depth={depth})")
    if depth >= 3:
        return RuleResult(True, 0.25, f"Multiple subdomains (depth={depth})")
    return RuleResult(False, 0.0, "")


def rule_keyword_density(url, parsed, hostname, reg_domain, full):
    """Multiple phishing keywords in a single URL."""
    hits = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if len(hits) >= 5:
        return RuleResult(True, 0.60, f"High keyword density: {hits[:5]}")
    if len(hits) >= 3:
        return RuleResult(True, 0.40, f"Multiple phishing keywords: {hits[:3]}")
    if len(hits) >= 1:
        return RuleResult(True, 0.15, f"Phishing keyword: {hits[0]}")
    return RuleResult(False, 0.0, "")


def rule_url_shortener(url, parsed, hostname, reg_domain, full):
    """URL shorteners hide the real destination."""
    if any(hostname == s or hostname.endswith('.' + s) for s in URL_SHORTENERS):
        return RuleResult(True, 0.45, f"URL shortener detected: {hostname}")
    return RuleResult(False, 0.0, "")


def rule_encoded_obfuscation(url, parsed, hostname, reg_domain, full):
    """Heavy URL encoding used to obfuscate phishing content."""
    pct_count = url.count('%')
    if pct_count >= 10:
        return RuleResult(True, 0.55, f"Heavy URL encoding ({pct_count} encoded chars)")
    if pct_count >= 4:
        return RuleResult(True, 0.25, f"URL encoding present ({pct_count} encoded chars)")
    return RuleResult(False, 0.0, "")


def rule_random_domain(url, parsed, hostname, reg_domain, full):
    """Randomly generated domain names (high entropy)."""
    domain_part = reg_domain.split('.')[0]
    if _looks_random(domain_part, threshold=3.8):
        return RuleResult(True, 0.40,
            f"Random-looking domain '{domain_part}' (entropy={_entropy(domain_part):.2f})")
    return RuleResult(False, 0.0, "")


def rule_http_only(url, parsed, hostname, reg_domain, full):
    """Plain HTTP (no TLS) is a weak but real signal."""
    if url.startswith('http://'):
        return RuleResult(True, 0.15, "HTTP protocol (no encryption)")
    return RuleResult(False, 0.0, "")


def rule_digits_in_domain(url, parsed, hostname, reg_domain, full):
    """Digits substituted for letters (paypa1.com, g00gle.com)."""
    domain_part = reg_domain.split('.')[0]
    digit_ratio = sum(c.isdigit() for c in domain_part) / max(len(domain_part), 1)
    if digit_ratio > 0.4:
        return RuleResult(True, 0.45, f"High digit ratio in domain ({digit_ratio:.0%})")
    if digit_ratio > 0.2:
        return RuleResult(True, 0.20, f"Digits in domain ({digit_ratio:.0%})")
    return RuleResult(False, 0.0, "")


def rule_suspicious_path_patterns(url, parsed, hostname, reg_domain, full):
    """Specific path patterns that are almost exclusively phishing."""
    DANGER_PATTERNS = [
        r'verify[-_]?account',
        r'secure[-_]?login',
        r'account[-_]?verify',
        r'login[-_]?secure',
        r'confirm[-_]?identity',
        r'update[-_]?info',
        r'reset[-_]?password',
        r'recover[-_]?account',
        r'suspended[-_]?account',
        r'unusual[-_]?activity',
        r'webscr',
        r'cmd=_s-xclick',
        r'phishing',
    ]
    path_query = (parsed.path + '?' + parsed.query).lower()
    for pattern in DANGER_PATTERNS:
        if re.search(pattern, path_query):
            return RuleResult(True, 0.70,
                f"Dangerous path pattern: '{pattern}'", hard_block=True)
    return RuleResult(False, 0.0, "")


# ── Rule registry (ordered: hard blocks first) ─────────────────────────────────

ALL_RULES = [
    rule_ip_address,
    rule_at_sign,
    rule_brand_impersonation,
    rule_suspicious_tld_plus_keyword,
    rule_punycode_homograph,
    rule_suspicious_path_patterns,
    rule_double_slash_redirect,
    rule_excessive_hyphens,
    rule_many_subdomains,
    rule_keyword_density,
    rule_url_shortener,
    rule_encoded_obfuscation,
    rule_random_domain,
    rule_digits_in_domain,
    rule_long_url,
    rule_suspicious_tld_only,
    rule_http_only,
]


# ── Public API ─────────────────────────────────────────────────────────────────

def run_rules(url: str) -> dict:
    """
    Run all rules against a URL.

    Returns:
        {
          'hard_block':    bool,   # True → skip ML, classify as Phishing immediately
          'rule_score':    float,  # 0–1 aggregate heuristic score
          'triggered':     list,   # list of triggered rule reason strings
          'top_reason':    str,    # most important triggered reason
        }
    """
    url = url.strip()
    try:
        parsed    = urlparse(url)
        hostname  = parsed.netloc.lower().split(':')[0]
        reg_domain = _get_registered_domain(hostname)
        full      = url.lower()
    except Exception:
        return {'hard_block': False, 'rule_score': 0.0, 'triggered': [], 'top_reason': ''}

    triggered_reasons = []
    total_score       = 0.0
    hard_block        = False

    for rule_fn in ALL_RULES:
        try:
            result = rule_fn(url, parsed, hostname, reg_domain, full)
            if result.triggered:
                triggered_reasons.append(result.reason)
                total_score += result.score
                if result.hard_block:
                    hard_block = True
        except Exception:
            continue

    # Clamp to [0, 1]
    total_score = min(total_score, 1.0)

    return {
        'hard_block':  hard_block,
        'rule_score':  round(total_score, 4),
        'triggered':   triggered_reasons,
        'top_reason':  triggered_reasons[0] if triggered_reasons else 'No suspicious signals',
    }
