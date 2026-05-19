"""
PhishGuard AI — Backend API
============================
Detection pipeline (in order):
  1. PhishTank blacklist  → instant hard-block
  2. Trusted whitelist    → instant safe
  3. Google Safe Browsing → hard-block if flagged
  4. Phishing rules engine → hard-block on obvious patterns
  5. ML ensemble          → stacked RF + GB + XGB + meta-classifier
  6. Combined score       → weighted blend of ML + heuristic
  7. Confidence boosting  → force high confidence when multiple signals agree
"""

import os
import sys
import csv
import re
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Path setup so utils/ is importable ────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils.feature_extraction import extract_features, extract_feature_vector, get_feature_names
from utils.phishing_rules import run_rules

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
)
logger = logging.getLogger('PhishGuardAI')

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=['*'], supports_credentials=True)

# ── Model loading ──────────────────────────────────────────────────────────────
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model')

def _load_model(name):
    path = os.path.join(MODEL_DIR, name)
    if os.path.exists(path):
        try:
            obj = joblib.load(path)
            logger.info(f'✅ Loaded {name}')
            return obj
        except Exception as e:
            logger.error(f'❌ Failed to load {name}: {e}')
    else:
        logger.warning(f'⚠️  Model file not found: {path}')
    return None

rf_model         = _load_model('rf_model.pkl')
gb_model         = _load_model('gb_model.pkl')
xgb_model        = _load_model('xgb_model.pkl')
meta_model       = _load_model('meta_model.pkl')
tfidf_vectorizer = _load_model('tfidf_vectorizer.pkl')
feature_scaler   = _load_model('feature_scaler.pkl')

# Legacy fallback — used if new models aren't trained yet
_legacy_model      = _load_model('phishing_model.pkl')
_legacy_vectorizer = _load_model('vectorizer.pkl')

_models_ready = (meta_model is not None) or (_legacy_model is not None)
logger.info(f'Models ready: {_models_ready}')


# ── Configuration ──────────────────────────────────────────────────────────────
class Config:
    # ── Thresholds ─────────────────────────────────────────
    PHISHING_THRESHOLD   = 0.65   # ≥ 65% → Phishing
    SUSPICIOUS_THRESHOLD = 0.45   # 45–65% → Suspicious
    # Below 45% → Legitimate

    # ── Confidence boosting ────────────────────────────────
    # When multiple strong signals agree, boost final score
    BOOST_THRESHOLD      = 0.55   # boost if score already above this
    BOOST_TARGET         = 0.87   # boost to at least this value

    # ── Blend weights ──────────────────────────────────────
    ML_WEIGHT        = 0.60
    HEURISTIC_WEIGHT = 0.40

    # ── Google Safe Browsing ───────────────────────────────
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', 'YOUR_GOOGLE_API_KEY_HERE')
    GOOGLE_SB_URL  = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

    # ── Trusted domains (exact + subdomain match) ──────────
    TRUSTED_DOMAINS = {
        'google.com', 'gmail.com', 'youtube.com',
        'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        'linkedin.com', 'github.com', 'stackoverflow.com',
        'amazon.com', 'microsoft.com', 'apple.com',
        'reddit.com', 'wikipedia.org', 'paypal.com', 'stripe.com',
        'velalarengg.ac.in',
    }

    # ── PhishTank blacklist path ───────────────────────────
    PHISHTANK_CSV = os.path.join(
        os.path.dirname(__file__), '..', 'backend', 'data', 'phishtank.csv'
    )


# ── PhishTank blacklist ────────────────────────────────────────────────────────
_phishtank_urls: set = set()

def _load_phishtank():
    global _phishtank_urls
    path = Config.PHISHTANK_CSV
    if not os.path.exists(path):
        logger.warning(f'PhishTank CSV not found at {path} — blacklist disabled')
        return
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            # PhishTank CSV columns: phish_id, url, phish_detail_url, ...
            url_col = None
            for col in ('url', 'URL', 'phish_url'):
                if col in (reader.fieldnames or []):
                    url_col = col
                    break
            if not url_col:
                logger.warning('PhishTank CSV has no url column')
                return
            for row in reader:
                u = row.get(url_col, '').strip()
                if u:
                    _phishtank_urls.add(u.lower())
        logger.info(f'✅ PhishTank blacklist loaded: {len(_phishtank_urls):,} URLs')
    except Exception as e:
        logger.error(f'Error loading PhishTank: {e}')

_load_phishtank()


def is_known_phishing(url: str) -> bool:
    """Check URL against PhishTank blacklist (exact match)."""
    return url.lower() in _phishtank_urls


# ── Domain helpers ─────────────────────────────────────────────────────────────

def normalize_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().replace('www.', '').split(':')[0]
    except Exception:
        return ''


def is_trusted(domain: str) -> bool:
    if not domain:
        return False
    for trusted in Config.TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            return True
    return False


# ── Google Safe Browsing ───────────────────────────────────────────────────────

def check_google_safe_browsing(url: str):
    if Config.GOOGLE_API_KEY == 'YOUR_GOOGLE_API_KEY_HERE':
        return None
    try:
        body = {
            'client': {'clientId': 'PhishGuardAI', 'clientVersion': '2.0.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}],
            },
        }
        resp = requests.post(
            Config.GOOGLE_SB_URL,
            json=body,
            params={'key': Config.GOOGLE_API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            threats = data.get('matches', [])
            return {'is_safe': len(threats) == 0, 'threats': threats}
    except Exception as e:
        logger.warning(f'Google Safe Browsing error: {e}')
    return None


# ── ML prediction ──────────────────────────────────────────────────────────────

def ml_predict(url: str, feature_vector: list) -> dict:
    """
    Run stacked ensemble. Falls back to legacy TF-IDF model if new models
    haven't been trained yet.
    """
    default = {'rf': 0.5, 'gb': 0.5, 'xgb': 0.5, 'meta': 0.5, 'method': 'unavailable'}

    X_feat = np.array(feature_vector, dtype=float).reshape(1, -1)

    # ── New ensemble path ──────────────────────────────────
    if meta_model is not None:
        try:
            if feature_scaler is not None:
                X_feat_scaled = feature_scaler.transform(X_feat)
            else:
                X_feat_scaled = X_feat

            rf_p = gb_p = xgb_p = 0.5

            if rf_model is not None:
                rf_p = float(rf_model.predict_proba(X_feat_scaled)[0][1])
            if gb_model is not None:
                gb_p = float(gb_model.predict_proba(X_feat_scaled)[0][1])
            if xgb_model is not None:
                xgb_p = float(xgb_model.predict_proba(X_feat_scaled)[0][1])

            meta_input = np.array([[rf_p, gb_p, xgb_p]])
            meta_p = float(meta_model.predict_proba(meta_input)[0][1])

            return {
                'rf': round(rf_p, 4),
                'gb': round(gb_p, 4),
                'xgb': round(xgb_p, 4),
                'meta': round(meta_p, 4),
                'method': 'ensemble',
            }
        except Exception as e:
            logger.error(f'Ensemble prediction error: {e}')

    # ── Legacy TF-IDF fallback ─────────────────────────────
    if _legacy_model is not None and _legacy_vectorizer is not None:
        try:
            vec = _legacy_vectorizer.transform([url])
            p = float(_legacy_model.predict_proba(vec)[0][1])
            return {'rf': p, 'gb': p, 'xgb': p, 'meta': p, 'method': 'legacy_tfidf'}
        except Exception as e:
            logger.error(f'Legacy prediction error: {e}')

    return default


# ── Score combination & boosting ───────────────────────────────────────────────

def combine_scores(ml_meta: float, rule_score: float, hard_block: bool) -> float:
    """
    Blend ML probability and heuristic rule score.
    Hard-block rules force the score to at least 0.90.
    """
    if hard_block:
        return max(0.90, ml_meta)

    blended = Config.ML_WEIGHT * ml_meta + Config.HEURISTIC_WEIGHT * rule_score
    return round(min(blended, 1.0), 4)


def apply_confidence_boost(score: float, rule_result: dict, ml_result: dict) -> float:
    """
    If multiple independent signals all agree the URL is phishing,
    boost the final score to at least BOOST_TARGET.
    Signals: rule_score, rf, gb, xgb all above 0.5.
    """
    if score < Config.BOOST_THRESHOLD:
        return score

    signals_agree = (
        rule_result['rule_score'] > 0.5
        and ml_result['rf']  > 0.5
        and ml_result['gb']  > 0.5
        and ml_result['xgb'] > 0.5
    )
    if signals_agree:
        return max(score, Config.BOOST_TARGET)
    return score


def classify(probability: float) -> tuple:
    """Return (prediction_label, risk_level)."""
    if probability >= Config.PHISHING_THRESHOLD:
        return 'Phishing', 'High Risk'
    if probability >= Config.SUSPICIOUS_THRESHOLD:
        return 'Suspicious', 'Medium Risk'
    return 'Legitimate', 'Low Risk'


# ── SHAP-style feature explanation ────────────────────────────────────────────

def build_feature_explanation(url: str, features: dict, rule_result: dict) -> list:
    """
    Build a list of feature dicts for the frontend to display.
    Each entry: {name, value, risk, description, shap_contribution}
    """
    items = []

    def risk_level(val, low_thresh, high_thresh, invert=False):
        if invert:
            return 'low' if val >= high_thresh else ('medium' if val >= low_thresh else 'high')
        return 'high' if val >= high_thresh else ('medium' if val >= low_thresh else 'low')

    # URL length
    items.append({
        'name': 'URL Length',
        'value': features['url_length'],
        'risk': risk_level(features['url_length'], 75, 120),
        'description': f"{features['url_length']} characters — {'suspicious' if features['url_length'] > 100 else 'normal'}",
        'shap_contribution': round((features['url_length'] - 50) / 200, 3),
    })

    # HTTPS
    items.append({
        'name': 'Protocol',
        'value': 'HTTPS' if features['is_https'] else 'HTTP',
        'risk': 'low' if features['is_https'] else 'high',
        'description': 'Encrypted connection' if features['is_https'] else 'No encryption — higher risk',
        'shap_contribution': -0.05 if features['is_https'] else 0.10,
    })

    # IP address
    if features['is_ip_address']:
        items.append({
            'name': 'IP Address Host',
            'value': 'Yes',
            'risk': 'high',
            'description': 'Raw IP used instead of domain name — strong phishing signal',
            'shap_contribution': 0.40,
        })

    # Brand impersonation
    if features['brand_in_subdomain_or_path']:
        items.append({
            'name': 'Brand Impersonation',
            'value': 'Detected',
            'risk': 'high',
            'description': 'Known brand name in URL but not in registered domain',
            'shap_contribution': 0.35,
        })

    # Suspicious TLD
    if features['suspicious_tld']:
        items.append({
            'name': 'Suspicious TLD',
            'value': 'Yes',
            'risk': 'high',
            'description': 'Top-level domain commonly used in phishing campaigns',
            'shap_contribution': 0.25,
        })

    # Phishing keywords
    if features['phishing_keyword_count'] > 0:
        items.append({
            'name': 'Phishing Keywords',
            'value': features['phishing_keyword_count'],
            'risk': risk_level(features['phishing_keyword_count'], 1, 3),
            'description': f"{features['phishing_keyword_count']} phishing-related keyword(s) found in URL",
            'shap_contribution': round(features['phishing_keyword_count'] * 0.08, 3),
        })

    # Hyphens in domain
    if features['domain_hyphen_count'] > 0:
        items.append({
            'name': 'Domain Hyphens',
            'value': features['domain_hyphen_count'],
            'risk': risk_level(features['domain_hyphen_count'], 1, 3),
            'description': f"{features['domain_hyphen_count']} hyphen(s) in domain — common in phishing",
            'shap_contribution': round(features['domain_hyphen_count'] * 0.07, 3),
        })

    # Subdomains
    if features['num_subdomains'] > 1:
        items.append({
            'name': 'Subdomain Depth',
            'value': features['num_subdomains'],
            'risk': risk_level(features['num_subdomains'], 2, 4),
            'description': f"{features['num_subdomains']} subdomain level(s) — deep nesting is suspicious",
            'shap_contribution': round(features['num_subdomains'] * 0.06, 3),
        })

    # Domain entropy
    items.append({
        'name': 'Domain Entropy',
        'value': round(features['domain_entropy'], 2),
        'risk': risk_level(features['domain_entropy'], 3.2, 3.8),
        'description': f"Entropy {features['domain_entropy']:.2f} — {'random-looking' if features['domain_entropy'] > 3.8 else 'normal'}",
        'shap_contribution': round((features['domain_entropy'] - 3.0) * 0.05, 3),
    })

    # @ sign
    if features['has_at_in_url']:
        items.append({
            'name': '@ in URL',
            'value': 'Yes',
            'risk': 'high',
            'description': '@ symbol tricks browser into ignoring the real host',
            'shap_contribution': 0.35,
        })

    # URL shortener
    if features['is_url_shortener']:
        items.append({
            'name': 'URL Shortener',
            'value': 'Yes',
            'risk': 'medium',
            'description': 'URL shortener hides the real destination',
            'shap_contribution': 0.20,
        })

    # Punycode / homograph
    if features['is_punycode'] or features['has_homograph']:
        items.append({
            'name': 'Homograph Attack',
            'value': 'Detected',
            'risk': 'high',
            'description': 'Punycode or non-ASCII characters used to spoof domain',
            'shap_contribution': 0.40,
        })

    # Sort by absolute shap contribution descending
    items.sort(key=lambda x: abs(x['shap_contribution']), reverse=True)
    return items[:12]  # top 12 features


# ── In-memory cache ────────────────────────────────────────────────────────────
_cache: dict = {}
_cache_ts: dict = {}
CACHE_TTL = timedelta(hours=1)


def _get_cache(url):
    if url in _cache and url in _cache_ts:
        if datetime.now() - _cache_ts[url] < CACHE_TTL:
            r = _cache[url].copy()
            r['from_cache'] = True
            return r
    return None


def _set_cache(url, result):
    _cache[url] = result
    _cache_ts[url] = datetime.now()


# ── Main prediction pipeline ───────────────────────────────────────────────────

def full_pipeline(url: str) -> dict:
    """
    Run the complete detection pipeline and return a result dict.
    """
    domain = normalize_domain(url)

    # ── Step 1: PhishTank blacklist ────────────────────────
    if is_known_phishing(url):
        return _build_result(url, domain, 'Phishing', 0.99, 'High Risk',
                             'phishtank_blacklist',
                             '🚨 URL found in PhishTank phishing database',
                             [], {}, {})

    # ── Step 2: Trusted whitelist ──────────────────────────
    if is_trusted(domain):
        return _build_result(url, domain, 'Legitimate', 0.01, 'Low Risk',
                             'trusted_whitelist',
                             '✅ Domain is in trusted whitelist',
                             [], {}, {})

    # ── Step 3: Google Safe Browsing ──────────────────────
    gsb = check_google_safe_browsing(url)
    if gsb and not gsb['is_safe']:
        return _build_result(url, domain, 'Phishing', 0.99, 'High Risk',
                             'google_safe_browsing',
                             '🚨 Flagged by Google Safe Browsing',
                             gsb.get('threats', []), {}, {})

    # ── Step 4: Feature extraction ─────────────────────────
    features     = extract_features(url)
    feat_vector  = list(features.values())

    # ── Step 5: Rules engine ───────────────────────────────
    rule_result  = run_rules(url)

    # Append heuristic_risk_score as the 42nd feature
    feat_vector.append(rule_result['rule_score'])

    # Hard-block: obvious phishing pattern detected by rules
    if rule_result['hard_block']:
        ml_result = ml_predict(url, feat_vector)
        final_score = max(0.90, ml_result['meta'])
        prediction, risk_level = classify(final_score)
        explanation = build_feature_explanation(url, features, rule_result)
        return _build_result(
            url, domain, prediction, final_score, risk_level,
            'rules_hard_block',
            f"🚨 {rule_result['top_reason']}",
            [], features, ml_result,
            rule_result=rule_result,
            explanation=explanation,
        )

    # ── Step 6: ML ensemble ────────────────────────────────
    ml_result = ml_predict(url, feat_vector)

    # ── Step 7: Combine scores ─────────────────────────────
    blended = combine_scores(ml_result['meta'], rule_result['rule_score'],
                             rule_result['hard_block'])

    # ── Step 8: Confidence boosting ────────────────────────
    final_score = apply_confidence_boost(blended, rule_result, ml_result)

    prediction, risk_level = classify(final_score)

    # Build note
    triggered = rule_result['triggered']
    if triggered:
        note = f"⚠️ Signals: {'; '.join(triggered[:2])}"
    else:
        note = f"URL analyzed — {round(final_score * 100, 1)}% phishing probability"

    explanation = build_feature_explanation(url, features, rule_result)

    return _build_result(
        url, domain, prediction, final_score, risk_level,
        ml_result['method'],
        note,
        [], features, ml_result,
        rule_result=rule_result,
        explanation=explanation,
    )


def _build_result(url, domain, prediction, probability, risk_level,
                  method, note, threats, features, ml_result,
                  rule_result=None, explanation=None):
    """Assemble the final response dict."""
    rule_result  = rule_result  or {'rule_score': 0.0, 'triggered': [], 'top_reason': ''}
    explanation  = explanation  or []
    ml_result    = ml_result    or {'rf': 0.5, 'gb': 0.5, 'xgb': 0.5, 'meta': 0.5}

    return {
        'url':                  url,
        'domain':               domain,
        'prediction':           prediction,
        'phishing_probability': round(float(probability), 4),
        'confidence_percentage': round(float(probability) * 100, 2),
        'risk_level':           risk_level,
        'detection_method':     method,
        'note':                 note,
        'threats':              threats,
        'timestamp':            datetime.now().isoformat(),
        'from_cache':           False,

        # Detailed breakdown for frontend
        'model_probs': {
            'random_forest':     ml_result.get('rf', 0.5),
            'gradient_boosting': ml_result.get('gb', 0.5),
            'xgboost':           ml_result.get('xgb', 0.5),
            'meta':              ml_result.get('meta', 0.5),
        },
        'rule_score':     rule_result['rule_score'],
        'triggered_rules': rule_result['triggered'],
        'top_reason':     rule_result['top_reason'],
        'features':       explanation,
        'shap_values':    _build_shap(explanation, probability),
    }


def _build_shap(explanation: list, probability: float) -> list:
    """Convert feature explanation to SHAP-style list for frontend chart."""
    shap_list = []
    for item in explanation:
        shap_list.append({
            'feature': item['name'].lower().replace(' ', '_'),
            'shap':    item['shap_contribution'],
        })
    # Pad with a baseline entry
    shap_list.append({'feature': 'base_rate', 'shap': round(probability - 0.5, 3)})
    return sorted(shap_list, key=lambda x: abs(x['shap']), reverse=True)


# ── API Routes ─────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':           'healthy',
        'timestamp':        datetime.now().isoformat(),
        'models_ready':     _models_ready,
        'blacklist_size':   len(_phishtank_urls),
        'whitelist_size':   len(Config.TRUSTED_DOMAINS),
        'google_api':       Config.GOOGLE_API_KEY != 'YOUR_GOOGLE_API_KEY_HERE',
    })


@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'GET':
        return jsonify({'message': 'Use POST', 'example': {'url': 'https://example.com'}}), 400

    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Invalid JSON body'}), 400

        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'Please provide a URL'}), 400
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400

        # Cache check
        cached = _get_cache(url)
        if cached:
            return jsonify(cached), 200

        result = full_pipeline(url)
        _set_cache(url, result)

        logger.info(f"[{result['prediction']}] {url} — {result['confidence_percentage']}%")
        return jsonify(result), 200

    except Exception as e:
        logger.exception(f'Unexpected error in /predict: {e}')
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500


@app.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    if request.method == 'GET':
        return jsonify({'whitelist': sorted(Config.TRUSTED_DOMAINS),
                        'count': len(Config.TRUSTED_DOMAINS)}), 200

    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').lower().strip()
    if not domain:
        return jsonify({'error': 'domain required'}), 400

    if request.method == 'POST':
        Config.TRUSTED_DOMAINS.add(domain)
        return jsonify({'message': f'✅ {domain} added', 'whitelist': sorted(Config.TRUSTED_DOMAINS)}), 200

    if request.method == 'DELETE':
        Config.TRUSTED_DOMAINS.discard(domain)
        return jsonify({'message': f'✅ {domain} removed', 'whitelist': sorted(Config.TRUSTED_DOMAINS)}), 200


@app.route('/blacklist/reload', methods=['POST'])
def reload_blacklist():
    """Reload PhishTank CSV without restarting the server."""
    _load_phishtank()
    return jsonify({'message': f'✅ Blacklist reloaded — {len(_phishtank_urls):,} URLs'}), 200


@app.route('/cache/clear', methods=['POST'])
def clear_cache():
    _cache.clear()
    _cache_ts.clear()
    return jsonify({'message': '✅ Cache cleared'}), 200


@app.route('/stats', methods=['GET'])
def stats():
    return jsonify({
        'cached_urls':      len(_cache),
        'models_ready':     _models_ready,
        'blacklist_size':   len(_phishtank_urls),
        'whitelist_size':   len(Config.TRUSTED_DOMAINS),
        'google_api':       Config.GOOGLE_API_KEY != 'YOUR_GOOGLE_API_KEY_HERE',
        'thresholds': {
            'phishing':    Config.PHISHING_THRESHOLD,
            'suspicious':  Config.SUSPICIOUS_THRESHOLD,
        },
    }), 200


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logger.info('🚀 PhishGuard AI starting...')
    app.run(
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
        host='0.0.0.0',
        port=5000,
    )
