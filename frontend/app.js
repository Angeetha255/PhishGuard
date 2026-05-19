/* ======================================================
   PhishGuard AI — Main Application Logic
   ====================================================== */

'use strict';

// ── Config ──────────────────────────────────────────────
const CONFIG = {
  apiBase: 'http://localhost:5000',
  apiTimeout: 15000,
  debounceMs: 200,
};

// ── State ────────────────────────────────────────────────
const state = {
  history: JSON.parse(localStorage.getItem('phishguard_history') || '[]'),
  currentResult: null,
  historyFilter: 'all',
  shapChart: null,
};

// ── DOM refs ─────────────────────────────────────────────
const $ = id => document.getElementById(id);

const DOM = {
  urlInput:        $('urlInput'),
  analyzeBtn:      $('analyzeBtn'),
  clearBtn:        $('clearBtn'),
  scanOverlay:     $('scanOverlay'),
  resultSection:   $('resultSection'),
  analyzerCard:    $('analyzerCard'),
  verdictBanner:   $('verdictBanner'),
  verdictIconWrap: $('verdictIconWrap'),
  verdictIcon:     $('verdictIcon'),
  verdictLabel:    $('verdictLabel'),
  verdictUrl:      $('verdictUrl'),
  confValue:       $('confValue'),
  confCircle:      $('confCircle'),
  featureTableBody:$('featureTableBody'),
  modelsGrid:      $('modelsGrid'),
  riskReport:      $('riskReport'),
  historyList:     $('historyList'),
  historyEmpty:    $('historyEmpty'),
  toast:           $('toast'),
  navbar:          $('navbar'),
  hamburger:       $('hamburger'),
  mobileDrawer:    $('mobileDrawer'),
  scanSteps:       {
    extract: $('step-extract'),
    predict: $('step-predict'),
    shap:    $('step-shap'),
    done:    $('step-done'),
  },
};

// ══════════════════════════════════════════════════════════
//  PARTICLE BACKGROUND
// ══════════════════════════════════════════════════════════
(function initParticles() {
  const canvas = $('particleCanvas');
  const ctx    = canvas.getContext('2d');
  let W, H, particles;

  const resize = () => {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  };

  const randomBetween = (a, b) => a + Math.random() * (b - a);

  const makeParticle = () => ({
    x:   Math.random() * W,
    y:   Math.random() * H,
    vx:  randomBetween(-.25, .25),
    vy:  randomBetween(-.25, .25),
    r:   randomBetween(.5, 1.8),
    alpha: randomBetween(.15, .5),
  });

  const init = () => {
    resize();
    particles = Array.from({ length: 110 }, makeParticle);
  };

  const draw = () => {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 130) {
          ctx.strokeStyle = `rgba(99,102,241,${0.08 * (1 - dist / 130)})`;
          ctx.lineWidth   = 0.6;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw particles
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(99,102,241,${p.alpha})`;
      ctx.fill();

      p.x += p.vx;
      p.y += p.vy;

      if (p.x < -5)     p.x = W + 5;
      if (p.x > W + 5)  p.x = -5;
      if (p.y < -5)     p.y = H + 5;
      if (p.y > H + 5)  p.y = -5;
    });

    requestAnimationFrame(draw);
  };

  window.addEventListener('resize', () => {
    resize();
    particles.forEach(p => {
      if (p.x > W) p.x = Math.random() * W;
      if (p.y > H) p.y = Math.random() * H;
    });
  });

  init();
  draw();
})();

// ══════════════════════════════════════════════════════════
//  NAVBAR — scroll & active link
// ══════════════════════════════════════════════════════════
window.addEventListener('scroll', () => {
  DOM.navbar.classList.toggle('scrolled', window.scrollY > 20);

  // Update active nav link
  const sections = ['hero','features','analyzer','history','about'];
  const scrollY = window.scrollY + 100;
  let active = 'hero';
  sections.forEach(id => {
    const el = document.getElementById(id);
    if (el && el.offsetTop <= scrollY) active = id;
  });

  document.querySelectorAll('.nav-link').forEach(l => {
    l.classList.toggle('active', l.id === `nav-${active}`);
  });
});

DOM.hamburger.addEventListener('click', () => {
  DOM.mobileDrawer.classList.toggle('open');
});

document.querySelectorAll('.mob-link').forEach(l => {
  l.addEventListener('click', () => DOM.mobileDrawer.classList.remove('open'));
});

// ══════════════════════════════════════════════════════════
//  URL INPUT HANDLING
// ══════════════════════════════════════════════════════════
DOM.urlInput.addEventListener('input', () => {
  const val = DOM.urlInput.value.trim();
  DOM.analyzeBtn.disabled = val.length < 4;
  DOM.clearBtn.style.display = val ? 'flex' : 'none';
});

DOM.urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !DOM.analyzeBtn.disabled) analyze();
});

DOM.clearBtn.addEventListener('click', () => {
  DOM.urlInput.value = '';
  DOM.analyzeBtn.disabled = true;
  DOM.clearBtn.style.display = 'none';
  DOM.urlInput.focus();
  hideResults();
});

// Example pills
document.querySelectorAll('.pill').forEach(pill => {
  pill.addEventListener('click', () => {
    DOM.urlInput.value = pill.dataset.url;
    DOM.analyzeBtn.disabled = false;
    DOM.clearBtn.style.display = 'flex';
    DOM.urlInput.focus();
  });
});

DOM.analyzeBtn.addEventListener('click', analyze);

// ══════════════════════════════════════════════════════════
//  SCAN ANIMATION STEPS
// ══════════════════════════════════════════════════════════
function runScanSteps() {
  const steps = ['extract','predict','shap','done'];
  const delays = [300, 900, 1600, 2200];
  steps.forEach((step, i) => {
    setTimeout(() => {
      // Mark previous as done
      if (i > 0) {
        DOM.scanSteps[steps[i-1]].classList.remove('active');
        DOM.scanSteps[steps[i-1]].classList.add('done');
      }
      DOM.scanSteps[step].classList.add('active');
    }, delays[i]);
  });
}

function resetScanSteps() {
  Object.values(DOM.scanSteps).forEach(el => {
    el.classList.remove('active','done');
  });
  DOM.scanSteps.extract.classList.add('active');
}

// ══════════════════════════════════════════════════════════
//  ANALYZE
// ══════════════════════════════════════════════════════════
async function analyze() {
  const url = DOM.urlInput.value.trim();
  if (!url || url.length < 4) return;

  // Show loading state
  DOM.analyzeBtn.querySelector('.btn-text').style.display = 'none';
  DOM.analyzeBtn.querySelector('.btn-loading').style.display = 'flex';
  DOM.analyzeBtn.disabled = true;

  hideResults();
  resetScanSteps();
  DOM.scanOverlay.style.display = 'flex';
  runScanSteps();

  let result;
  try {
    result = await fetchAnalysis(url);
    
    // Min display time for animation
    await sleep(2800);

    DOM.scanOverlay.style.display = 'none';
    DOM.analyzeBtn.querySelector('.btn-text').style.display = 'flex';
    DOM.analyzeBtn.querySelector('.btn-loading').style.display = 'none';
    DOM.analyzeBtn.disabled = false;

    state.currentResult = result;
    renderResult(result);
    addToHistory(result);
  } catch (err) {
    DOM.scanOverlay.style.display = 'none';
    DOM.analyzeBtn.querySelector('.btn-text').style.display = 'flex';
    DOM.analyzeBtn.querySelector('.btn-loading').style.display = 'none';
    DOM.analyzeBtn.disabled = false;
    
    console.error('🚨 Analyze error:', err.message, err);
    if (err.name !== 'AbortError') {
      showToast(`❌ Error: ${err.message || 'Failed to analyze URL. Make sure backend is running.'}`, 'error');
    } else {
      showToast('Request timeout. Please try again.', 'error');
    }
  }
}

async function fetchAnalysis(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CONFIG.apiTimeout);

  try {
    console.log(`🔍 Fetching from: ${CONFIG.apiBase}/predict`);
    const res = await fetch(`${CONFIG.apiBase}/predict`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
      signal:  controller.signal,
    });
    clearTimeout(timer);

    console.log(`📡 Response status: ${res.status}`);
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`HTTP ${res.status}: ${errText}`);
    }
    
    const apiResponse = await res.json();
    console.log(`✅ API Response:`, apiResponse);
    
    const transformed = transformApiResponse(apiResponse);
    console.log(`🔄 Transformed Response:`, transformed);
    return transformed;
  } catch (err) {
    console.error(`❌ fetchAnalysis error:`, err);
    throw err;
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ══════════════════════════════════════════════════════════
//  RENDER RESULT
// ══════════════════════════════════════════════════════════
function renderResult(result) {
  const isPhish = result.is_phishing;
  const confPct = result.confidence * 100;
  const conf    = confPct.toFixed(1);
  
  // Note: "confidence" = phishing_probability (0-100%)
  // Low % = Safe (legitimate), High % = Risky (phishing)
  // E.g., 1.8% phishing probability = 98.2% legitimate
  
  // Determine verdict based on prediction field directly (most reliable)
  let verdict = 'legitimate'; // default
  if (result.prediction === 'Phishing') {
    verdict = 'phishing';
  } else if (result.prediction === 'Suspicious') {
    verdict = 'suspicious';
  } else if (isPhish) {
    // Fallback: use confidence if prediction field is missing
    if (confPct > 50) {
      verdict = 'phishing';
    } else if (confPct > 30) {
      verdict = 'suspicious';
    }
  }

  // Verdict banner
  DOM.verdictBanner.className = `verdict-banner ${verdict}`;
  
  // Set icon and label based on verdict
  if (verdict === 'phishing') {
    DOM.verdictIcon.textContent  = '🚫';
    DOM.verdictLabel.textContent = '🚫 PHISHING URL';
  } else if (verdict === 'suspicious') {
    DOM.verdictIcon.textContent  = '⚠️';
    DOM.verdictLabel.textContent = '⚠️ SUSPICIOUS URL';
  } else {
    DOM.verdictIcon.textContent  = '✅';
    DOM.verdictLabel.textContent = '✅ LEGITIMATE URL';
  }
  
  DOM.verdictUrl.textContent   = result.url;

  // Confidence circle
  DOM.confValue.textContent = `${conf}%`;
  DOM.confValue.style.color = verdict === 'phishing' ? 'var(--red-l)' : verdict === 'suspicious' ? 'var(--orange)' : 'var(--green-l)';
  DOM.confCircle.style.stroke = verdict === 'phishing' ? '#ef4444' : verdict === 'suspicious' ? '#f97316' : '#22c55e';

  const dashoff = 314 - (314 * parseFloat(conf) / 100);
  setTimeout(() => {
    DOM.confCircle.style.strokeDashoffset = dashoff;
  }, 100);

  // Render tabs
  console.log('🔍 model_probs:', result.model_probs);
  renderShapChart(result.shap_values);
  renderFeatureTable(result.features);
  renderModelCards(result.model_probs, result.is_phishing);
  renderRiskReport(result);

  // Reset tabs
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  $('tab-shap').classList.add('active');
  $('panel-shap').classList.add('active');

  DOM.resultSection.style.display = 'block';
  DOM.resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── SHAP Chart ───────────────────────────────────────────
function renderShapChart(shapValues) {
  const ctx = $('shapChart').getContext('2d');
  if (state.shapChart) state.shapChart.destroy();

  const top = shapValues.slice(0, 10);
  const labels = top.map(s => s.feature.replace(/_/g, ' '));
  const values = top.map(s => s.shap);
  const colors = values.map(v => v > 0
    ? `rgba(239,68,68,${Math.min(0.3 + Math.abs(v) * 1.5, 0.9)})`
    : `rgba(34,197,94,${Math.min(0.3 + Math.abs(v) * 1.5, 0.9)})`
  );
  const borderColors = values.map(v => v > 0 ? 'rgba(239,68,68,1)' : 'rgba(34,197,94,1)');

  state.shapChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'SHAP Value',
        data: values,
        backgroundColor: colors,
        borderColor: borderColors,
        borderWidth: 1.5,
        borderRadius: 6,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 800, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d1528',
          borderColor: 'rgba(99,102,241,.3)',
          borderWidth: 1,
          titleColor: '#f1f5f9',
          bodyColor: '#94a3b8',
          callbacks: {
            label: ctx => ` SHAP: ${ctx.parsed.x > 0 ? '+' : ''}${ctx.parsed.x.toFixed(4)}`,
          },
        },
      },
      scales: {
        x: {
          grid:  { color: 'rgba(255,255,255,.05)' },
          ticks: { color: '#64748b', font: { size: 11 } },
          border:{ color: 'rgba(255,255,255,.07)' },
        },
        y: {
          grid:  { display: false },
          ticks: { color: '#94a3b8', font: { size: 11, family: 'Inter' } },
          border:{ color: 'rgba(255,255,255,.07)' },
        },
      },
    },
  });
}

// ── Feature Table ────────────────────────────────────────
function renderFeatureTable(features) {
  const riskIcon = r => r === 'high' ? '🔴' : r === 'medium' ? '🟡' : '🟢';

  DOM.featureTableBody.innerHTML = features.map(f => `
    <tr>
      <td class="feature-name">${f.name}</td>
      <td class="feature-value">${f.value}</td>
      <td>
        <span class="risk-badge risk-${f.risk}">
          ${riskIcon(f.risk)} ${f.risk.toUpperCase()}
        </span>
      </td>
      <td>${f.description}</td>
    </tr>
  `).join('');
}

// ── Model Cards ──────────────────────────────────────────
function renderModelCards(modelProbs, isPhishing) {
  const models = [
    { key: 'random_forest',     label: 'Random Forest',     icon: '🌲' },
    { key: 'gradient_boosting', label: 'Gradient Boosting', icon: '⚡' },
    { key: 'xgboost',           label: 'XGBoost',           icon: '🚀' },
  ];

  DOM.modelsGrid.innerHTML = models.map(m => {
    const prob    = modelProbs[m.key] ?? 0.5;
    const pct     = (prob * 100).toFixed(1);
    const isPhish = prob > 0.5;
    const dashoff = 201 * (1 - prob); // Dash offset for filled portion
    const strokeColor = isPhish ? '#ef4444' : '#22c55e';
    const uid = `gauge-${m.key}`;

    return `
      <div class="model-card">
        <div class="model-name">${m.icon} ${m.label}</div>
        <div class="model-gauge">
          <svg class="model-gauge-svg" width="80" height="80" viewBox="0 0 80 80">
            <circle cx="40" cy="40" r="32" class="gauge-track"/>
            <circle cx="40" cy="40" r="32" class="gauge-fill" id="${uid}"
              style="stroke:${strokeColor}; stroke-dashoffset:201; stroke-dasharray:201;"/>
          </svg>
          <div class="model-prob-text" style="color:${strokeColor}">${pct}%</div>
        </div>
        <div class="model-verdict ${isPhish ? 'phishing' : 'legit'}">
          ${isPhish ? '⚠️ Phishing' : '✅ Legitimate'}
        </div>
      </div>
    `;
  }).join('');

  // Animate gauges
  requestAnimationFrame(() => {
    models.forEach((m, index) => {
      const prob = modelProbs[m.key] ?? 0.5;
      const el   = document.getElementById(`gauge-${m.key}`);
      if (el) {
        setTimeout(() => {
          el.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)';
          el.style.strokeDashoffset = 201 * (1 - prob);
        }, 50 + index * 150);
      }
    });
  });
}

// ── Risk Report ──────────────────────────────────────────
function renderRiskReport(result) {
  const isPhish = result.is_phishing;
  const conf    = (result.confidence * 100).toFixed(1);
  const url     = result.url;

  let domain = '–';
  try { domain = new URL(url.startsWith('http') ? url : `http://${url}`).hostname; } catch {}

  const riskItems = [
    {
      icon:  isPhish ? '🚨' : '✅',
      label: 'Overall Verdict',
      value: isPhish
        ? `Classified as PHISHING with ${conf}% confidence`
        : `Classified as LEGITIMATE with ${conf}% confidence`,
    },
    {
      icon:  '🌐',
      label: 'Domain Analysis',
      value: `Domain: ${domain} — ${isPhish ? 'Suspicious patterns detected' : 'No suspicious patterns found'}`,
    },
    {
      icon:  url.startsWith('https') ? '🔒' : '⛔',
      label: 'Protocol Security',
      value: url.startsWith('https')
        ? 'HTTPS protocol detected — encrypted connection'
        : 'HTTP protocol — no encryption, higher risk',
    },
    {
      icon:  '🤖',
      label: 'Model Ensemble',
      value: `Random Forest, Gradient Boosting & XGBoost all evaluated. Meta-classifier produced final output.`,
    },
    {
      icon:  '💡',
      label: 'SHAP Insights',
      value: isPhish
        ? `Top risk features: ${(result.shap_values || []).filter(s => s.shap > 0).slice(0,3).map(s => s.feature.replace(/_/g,' ')).join(', ')}`
        : `Top safe signals: ${(result.shap_values || []).filter(s => s.shap < 0).slice(0,3).map(s => s.feature.replace(/_/g,' ')).join(', ')}`,
    },
    {
      icon:  '📋',
      label: 'Recommendation',
      value: isPhish
        ? '⚠️ Do NOT click this link. Report it to your security team and block the domain.'
        : '✅ URL appears safe. Always verify sender context and exercise caution.',
    },
  ];

  DOM.riskReport.innerHTML = riskItems.map(item => `
    <div class="risk-item">
      <div class="risk-item-icon">${item.icon}</div>
      <div>
        <div class="risk-item-label">${item.label}</div>
        <div class="risk-item-value">${item.value}</div>
      </div>
    </div>
  `).join('');
}

// ── Hide Results ─────────────────────────────────────────
function hideResults() {
  DOM.resultSection.style.display = 'none';
  DOM.scanOverlay.style.display = 'none';
  if (state.shapChart) { state.shapChart.destroy(); state.shapChart = null; }
}

// ── Result Action Buttons ────────────────────────────────
$('analyzeAnotherBtn').addEventListener('click', () => {
  hideResults();
  DOM.urlInput.focus();
  window.scrollTo({ top: $('analyzer').offsetTop - 80, behavior: 'smooth' });
});

$('copyReportBtn').addEventListener('click', () => {
  if (!state.currentResult) return;
  const r = state.currentResult;
  const report = [
    `PhishGuard AI — Analysis Report`,
    `URL: ${r.url}`,
    `Verdict: ${r.is_phishing ? 'PHISHING' : 'LEGITIMATE'}`,
    `Confidence: ${(r.confidence * 100).toFixed(1)}%`,
    `Timestamp: ${new Date().toISOString()}`,
    '',
    `Model Probabilities:`,
    `  Random Forest:     ${((r.model_probs?.random_forest || 0)*100).toFixed(2)}%`,
    `  Gradient Boosting: ${((r.model_probs?.gradient_boosting || 0)*100).toFixed(2)}%`,
    `  XGBoost:           ${((r.model_probs?.xgboost || 0)*100).toFixed(2)}%`,
  ].join('\n');

  navigator.clipboard.writeText(report)
    .then(() => showToast('Report copied to clipboard!', 'success'))
    .catch(() => showToast('Could not copy report', 'error'));
});

// ══════════════════════════════════════════════════════════
//  TABS
// ══════════════════════════════════════════════════════════
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    $(`panel-${tab}`).classList.add('active');
  });
});

// ══════════════════════════════════════════════════════════
//  HISTORY
// ══════════════════════════════════════════════════════════
function addToHistory(result) {
  const entry = {
    url:         result.url,
    is_phishing: result.is_phishing,
    confidence:  result.confidence,
    timestamp:   Date.now(),
  };
  state.history.unshift(entry);
  if (state.history.length > 50) state.history.pop();
  localStorage.setItem('phishguard_history', JSON.stringify(state.history));
  renderHistory();
}

function renderHistory() {
  const filter  = state.historyFilter;
  const entries = state.history.filter(h => {
    if (filter === 'phishing')   return h.is_phishing;
    if (filter === 'legitimate') return !h.is_phishing;
    return true;
  });

  DOM.historyEmpty.style.display = entries.length === 0 ? 'flex' : 'none';

  // Remove existing items
  document.querySelectorAll('.history-item').forEach(el => el.remove());

  entries.forEach(entry => {
    const el = document.createElement('div');
    el.className = `history-item`;
    el.innerHTML = `
      <div class="history-verdict-dot ${entry.is_phishing ? 'phishing' : 'legit'}"></div>
      <div class="history-url">${entry.url}</div>
      <span class="history-badge ${entry.is_phishing ? 'phishing' : 'legit'}">
        ${entry.is_phishing ? '⚠️ Phishing' : '✅ Legit'}
      </span>
      <span class="history-conf">${(entry.confidence * 100).toFixed(0)}%</span>
      <span class="history-time">${timeAgo(entry.timestamp)}</span>
    `;
    el.addEventListener('click', () => {
      DOM.urlInput.value = entry.url;
      DOM.analyzeBtn.disabled = false;
      DOM.clearBtn.style.display = 'flex';
      window.scrollTo({ top: $('analyzer').offsetTop - 80, behavior: 'smooth' });
    });
    DOM.historyList.appendChild(el);
  });
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)    return 'just now';
  if (diff < 3600000)  return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.historyFilter = btn.dataset.filter;
    renderHistory();
  });
});

$('clearHistoryBtn').addEventListener('click', () => {
  state.history = [];
  localStorage.removeItem('phishguard_history');
  renderHistory();
  showToast('History cleared', 'success');
});

// Initial render
renderHistory();

// ══════════════════════════════════════════════════════════
//  TOAST
// ══════════════════════════════════════════════════════════
let toastTimer;
function showToast(msg, type = 'success') {
  clearTimeout(toastTimer);
  DOM.toast.textContent = msg;
  DOM.toast.className   = `toast ${type} show`;
  toastTimer = setTimeout(() => {
    DOM.toast.classList.remove('show');
  }, 3500);
}

// ══════════════════════════════════════════════════════════
//  INTERSECTION OBSERVER — animate cards on scroll
// ══════════════════════════════════════════════════════════
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const delay = entry.target.dataset.delay || 0;
      setTimeout(() => {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }, parseInt(delay));
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.1 });

document.querySelectorAll('.feature-card, .arch-step').forEach(card => {
  card.style.opacity = '0';
  card.style.transform = 'translateY(24px)';
  card.style.transition = 'opacity .5s ease, transform .5s ease';
  observer.observe(card);
});

// ══════════════════════════════════════════════════════════
//  COUNTER ANIMATION (hero stats)
// ══════════════════════════════════════════════════════════
function animateCounter(el, end, suffix = '', duration = 1500) {
  const start = 0;
  const startTime = performance.now();
  const endNum  = parseFloat(end);

  const step = (now) => {
    const elapsed  = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const ease     = 1 - Math.pow(1 - progress, 3);
    const value    = start + (endNum - start) * ease;
    el.textContent = value.toFixed(end.toString().includes('.') ? 1 : 0) + suffix;
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

const statsObserver = new IntersectionObserver(entries => {
  if (entries[0].isIntersecting) {
    animateCounter($('stat-accuracy'), 98.7, '%');
    animateCounter($('stat-fp'),       0.3,  '%', 1000);
    animateCounter($('stat-features'), 42,   '+', 1200);
    animateCounter($('stat-models'),   3,    '',  800);
    statsObserver.disconnect();
  }
}, { threshold: 0.5 });

statsObserver.observe($('stat-accuracy'));

console.log('%c⚡ PhishGuard AI — Loaded', 'color:#6366f1;font-size:14px;font-weight:700');
console.log('%cConnect Flask backend at http://localhost:5000 for live predictions', 'color:#94a3b8;font-size:11px');