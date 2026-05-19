"""
PhishGuard AI — Prediction Utilities
======================================
Handles loading models and running predictions.
Kept separate so app.py stays clean.
"""

import os
import joblib
import numpy as np
import logging

logger = logging.getLogger(__name__)

# ── Model registry ─────────────────────────────────────────────────────────────
# Loaded once at import time; None if file is missing.

_BASE = os.path.join(os.path.dirname(__file__), '..', 'backend', 'model')

def _load(name):
    path = os.path.join(_BASE, name)
    if os.path.exists(path):
        try:
            obj = joblib.load(path)
            logger.info(f"✅ Loaded {name}")
            return obj
        except Exception as e:
            logger.error(f"❌ Failed to load {name}: {e}")
    return None


rf_model        = _load('rf_model.pkl')
gb_model        = _load('gb_model.pkl')
xgb_model       = _load('xgb_model.pkl')
meta_model      = _load('meta_model.pkl')
tfidf_vectorizer = _load('tfidf_vectorizer.pkl')
feature_scaler  = _load('feature_scaler.pkl')


def models_available() -> bool:
    return meta_model is not None


def predict_url(url: str, feature_vector: list) -> dict:
    """
    Run the full stacked ensemble prediction.

    Args:
        url:            Raw URL string (for TF-IDF)
        feature_vector: 42-element list from extract_feature_vector()

    Returns dict with keys:
        probability      – final phishing probability (0–1)
        rf_prob          – Random Forest probability
        gb_prob          – Gradient Boosting probability
        xgb_prob         – XGBoost probability
        meta_prob        – Meta-classifier probability
        method           – 'ensemble' | 'tfidf_only' | 'features_only' | 'unavailable'
    """
    result = {
        'probability': 0.5,
        'rf_prob':  0.5,
        'gb_prob':  0.5,
        'xgb_prob': 0.5,
        'meta_prob': 0.5,
        'method': 'unavailable',
    }

    if not models_available():
        return result

    try:
        X_feat = np.array(feature_vector, dtype=float).reshape(1, -1)

        # Scale features if scaler is available
        if feature_scaler is not None:
            X_feat = feature_scaler.transform(X_feat)

        # TF-IDF features
        X_tfidf = None
        if tfidf_vectorizer is not None:
            X_tfidf = tfidf_vectorizer.transform([url])

        # ── Base model predictions ──────────────────────────
        rf_p = gb_p = xgb_p = 0.5

        if rf_model is not None:
            try:
                rf_p = float(rf_model.predict_proba(X_feat)[0][1])
            except Exception:
                pass

        if gb_model is not None:
            try:
                gb_p = float(gb_model.predict_proba(X_feat)[0][1])
            except Exception:
                pass

        if xgb_model is not None:
            try:
                xgb_p = float(xgb_model.predict_proba(X_feat)[0][1])
            except Exception:
                pass

        # ── Meta-classifier ─────────────────────────────────
        # Meta input: [rf_prob, gb_prob, xgb_prob, tfidf_prob (if available)]
        tfidf_p = 0.5
        if tfidf_vectorizer is not None and X_tfidf is not None:
            try:
                # Use a simple RF on TF-IDF if meta_model expects it
                tfidf_p = float(meta_model.predict_proba(
                    np.array([[rf_p, gb_p, xgb_p]])
                )[0][1])
            except Exception:
                pass

        meta_input = np.array([[rf_p, gb_p, xgb_p]])
        try:
            meta_p = float(meta_model.predict_proba(meta_input)[0][1])
        except Exception:
            # Fallback: weighted average
            meta_p = 0.4 * rf_p + 0.3 * gb_p + 0.3 * xgb_p

        result.update({
            'probability': round(meta_p, 4),
            'rf_prob':     round(rf_p, 4),
            'gb_prob':     round(gb_p, 4),
            'xgb_prob':    round(xgb_p, 4),
            'meta_prob':   round(meta_p, 4),
            'method':      'ensemble',
        })

    except Exception as e:
        logger.error(f"Prediction error: {e}")

    return result
