/**
 * PhishGuard AI — API Response Adapter v2
 * =========================================
 * Transforms the backend response into the shape the frontend expects.
 *
 * Backend response shape (v2):
 * {
 *   url, domain, prediction, phishing_probability, confidence_percentage,
 *   risk_level, detection_method, note, threats, timestamp, from_cache,
 *   model_probs: { random_forest, gradient_boosting, xgboost, meta },
 *   rule_score, triggered_rules, top_reason,
 *   features: [ { name, value, risk, description, shap_contribution } ],
 *   shap_values: [ { feature, shap } ]
 * }
 */

function transformApiResponse(apiResponse) {
  if (!apiResponse) return null;

  const prediction          = apiResponse.prediction || 'Unknown';
  const probability         = apiResponse.phishing_probability ?? 0;
  const confidencePct       = apiResponse.confidence_percentage ?? (probability * 100);
  const isPhishing          = prediction === 'Phishing';
  const isSuspicious        = prediction === 'Suspicious';
  const detectionMethod     = apiResponse.detection_method || 'unknown';

  // ── Model probabilities ──────────────────────────────────
  const modelProbs = apiResponse.model_probs || {};
  const modelProbsNorm = {
    random_forest:     modelProbs.random_forest     ?? modelProbs.rf  ?? probability,
    gradient_boosting: modelProbs.gradient_boosting ?? modelProbs.gb  ?? probability,
    xgboost:           modelProbs.xgboost           ?? modelProbs.xgb ?? probability,
  };

  // ── Features ─────────────────────────────────────────────
  // Use real features from backend if available, otherwise generate mock
  const features = (apiResponse.features && apiResponse.features.length > 0)
    ? apiResponse.features
    : generateMockFeatures(apiResponse.url, probability);

  // ── SHAP values ──────────────────────────────────────────
  const shapValues = (apiResponse.shap_values && apiResponse.shap_values.length > 0)
    ? apiResponse.shap_values
    : generateMockShapValues(probability);

  return {
    // Core fields
    url:                apiResponse.url,
    domain:             apiResponse.domain,
    timestamp:          apiResponse.timestamp,
    from_cache:         apiResponse.from_cache || false,

    // Verdict
    is_phishing:        isPhishing || isSuspicious,
    prediction:         prediction,
    confidence:         Math.max(0, Math.min(1, probability)),
    confidence_percentage: confidencePct,
    risk_level:         apiResponse.risk_level || 'Unknown',
    detection_method:   detectionMethod,
    note:               apiResponse.note || '',

    // Threats (Google Safe Browsing)
    threats:            apiResponse.threats || [],

    // Rule engine output
    rule_score:         apiResponse.rule_score ?? 0,
    triggered_rules:    apiResponse.triggered_rules || [],
    top_reason:         apiResponse.top_reason || '',

    // ML model breakdown
    model_probs:        modelProbsNorm,

    // Feature table & SHAP chart
    features:           features,
    shap_values:        shapValues,

    demo_mode:          false,
  };
}

// ── Mock generators (fallback when backend doesn't return details) ─────────────

function generateMockFeatures(url, probability) {
  if (!url) return [];
  const isHttp = url.startsWith('http://');
  const length  = url.length;
  const dots    = (url.match(/\./g) || []).length;
  const hyphens = (url.match(/-/g) || []).length;
  const specials = (url.match(/[@%_]/g) || []).length;

  return [
    {
      name: 'URL Length',
      value: length,
      risk: length > 120 ? 'high' : length > 75 ? 'medium' : 'low',
      description: `${length} characters`,
      shap_contribution: (length - 50) / 300,
    },
    {
      name: 'Protocol',
      value: isHttp ? 'HTTP' : 'HTTPS',
      risk: isHttp ? 'high' : 'low',
      description: isHttp ? 'No encryption' : 'Encrypted connection',
      shap_contribution: isHttp ? 0.10 : -0.05,
    },
    {
      name: 'Dots in URL',
      value: dots,
      risk: dots > 5 ? 'high' : dots > 3 ? 'medium' : 'low',
      description: `${dots} dots — ${dots > 4 ? 'excessive subdomains' : 'normal'}`,
      shap_contribution: (dots - 2) * 0.04,
    },
    {
      name: 'Hyphens in Domain',
      value: hyphens,
      risk: hyphens >= 3 ? 'high' : hyphens >= 1 ? 'medium' : 'low',
      description: `${hyphens} hyphen(s) in URL`,
      shap_contribution: hyphens * 0.06,
    },
    {
      name: 'Special Characters',
      value: specials,
      risk: specials >= 3 ? 'high' : specials >= 1 ? 'medium' : 'low',
      description: `${specials} suspicious special character(s)`,
      shap_contribution: specials * 0.07,
    },
  ];
}

function generateMockShapValues(probability) {
  const p = probability;
  return [
    { feature: 'phishing_probability',  shap:  p * 0.35 },
    { feature: 'url_entropy',           shap:  p * 0.18 },
    { feature: 'special_characters',    shap:  p * 0.12 },
    { feature: 'suspicious_keywords',   shap:  p * 0.10 },
    { feature: 'domain_length',         shap:  p * 0.07 },
    { feature: 'domain_age',            shap: -(1 - p) * 0.18 },
    { feature: 'https_protocol',        shap: -(1 - p) * 0.12 },
    { feature: 'tld_reputation',        shap: -(1 - p) * 0.10 },
    { feature: 'domain_whois_age',      shap: -(1 - p) * 0.08 },
    { feature: 'certificate_status',    shap: -(1 - p) * 0.06 },
  ].map(f => ({ ...f, shap: Math.max(-0.5, Math.min(0.5, f.shap)) }))
   .sort((a, b) => Math.abs(b.shap) - Math.abs(a.shap));
}

function generateMockModelProbs(probability) {
  const v = 0.07;
  return {
    random_forest:     Math.max(0, Math.min(1, probability + (Math.random() - 0.5) * v)),
    gradient_boosting: Math.max(0, Math.min(1, probability + (Math.random() - 0.5) * v)),
    xgboost:           Math.max(0, Math.min(1, probability + (Math.random() - 0.5) * v)),
  };
}

function generateMockResult(url) {
  const prob = Math.random();
  const mock = {
    url,
    domain:               '',
    prediction:           prob > 0.65 ? 'Phishing' : prob > 0.45 ? 'Suspicious' : 'Legitimate',
    phishing_probability: prob,
    confidence_percentage: prob * 100,
    risk_level:           prob > 0.65 ? 'High Risk' : prob > 0.45 ? 'Medium Risk' : 'Low Risk',
    detection_method:     'demo_mock',
    note:                 '📊 Demo mode — real prediction requires Flask backend',
    timestamp:            new Date().toISOString(),
    from_cache:           false,
  };
  try { mock.domain = new URL(url).hostname; } catch {}
  const result = transformApiResponse(mock);
  result.demo_mode = true;
  return result;
}

// ── Export ─────────────────────────────────────────────────────────────────────
window.apiAdapter = {
  transformApiResponse,
  generateMockResult,
  generateMockFeatures,
  generateMockShapValues,
  generateMockModelProbs,
};
