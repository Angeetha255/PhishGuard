# PhishGuard AI - Detection Logic Overview

## 🎯 How the System Works

The phishing detection system uses a **3-tier detection pipeline**:

---

## 🔒 Tier 1: Trusted Whitelist Check

**When**: Checked FIRST for all URLs
**How**: Checks if domain is in trusted domain list

### Trusted Domains (Auto-Detected as Legitimate):
- ✅ `google.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `gmail.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `github.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `facebook.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `linkedin.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `twitter.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `amazon.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `microsoft.com` → 0% Phishing Risk → **LEGITIMATE**
- ✅ `apple.com` → 0% Phishing Risk → **LEGITIMATE**

**Verdict**: ✅ **LEGITIMATE URL** (Green checkmark, 0% risk)

---

## 🚨 Tier 2: Google Safe Browsing API Check

**When**: If URL is NOT in whitelist
**How**: Checks against Google's malware/phishing database

### Detected as Phishing:
- 🚫 `paypa1-secure-login.xyz` → Google flags as malware → **PHISHING**
- 🚫 `amazon-account-verify.ru` → Google flags as phishing → **PHISHING**
- 🚫 Any URL flagged by Google → 99% Phishing Risk → **PHISHING**

**Verdict**: 🚫 **PHISHING URL** (Red X, 99% risk)

---

## 🤖 Tier 3: ML Model Ensemble Check

**When**: If URL passes Tiers 1 & 2 (not whitelist, not flagged by Google)
**How**: Uses 3 ML models + meta-classifier to analyze 42+ URL features

### ML Model Probability Ranges:

| Phishing Probability | Verdict | Display |
|---|---|---|
| **0% - 35%** | ✅ LEGITIMATE | Green checkmark, low risk |
| **35% - 70%** | ⚠️ SUSPICIOUS | Orange warning, medium risk |
| **70% - 100%** | 🚫 PHISHING | Red X, high risk |

### Examples:

#### ✅ Detected as LEGITIMATE (0-35% phishing probability):
- `https://www.velalarengg.ac.in/` → 1.8% phishing risk → **LEGITIMATE**
- `https://university.edu/login` → 5% phishing risk → **LEGITIMATE**
- `https://company.com/careers` → 12% phishing risk → **LEGITIMATE**

#### ⚠️ Detected as SUSPICIOUS (35-70% phishing probability):
- `https://paypa1-secure.com/verify` → 45% phishing risk → **SUSPICIOUS**
- `https://amaz0n-login.net/account` → 52% phishing risk → **SUSPICIOUS**
- `https://banking-update-now.biz` → 68% phishing risk → **SUSPICIOUS**

#### 🚫 Detected as PHISHING (70-100% phishing probability):
- `https://goog1e-verify.xyz` → 85% phishing risk → **PHISHING**
- `https://paypal-secure.ru/login` → 92% phishing risk → **PHISHING**
- `https://bank-urgent-action.tk` → 98% phishing risk → **PHISHING**

---

## 📊 Feature Analysis (What ML Model Checks)

The system extracts **42+ features** including:

### URL Structure Features:
- ✅ URL length (shorter = safer)
- ✅ Special characters (@, -, _)
- ✅ Domain parts (subdomain levels)
- ✅ Protocol (HTTPS vs HTTP)

### Domain Features:
- ✅ TLD reputation (`.com` > `.tk`)
- ✅ Domain age (old domains = safer)
- ✅ Domain registration info
- ✅ WHOIS data

### Content Features:
- ✅ Suspicious keywords ("verify", "urgent", "confirm")
- ✅ Obfuscation techniques
- ✅ Brand name confusion
- ✅ Homograph attacks

---

## 🔄 Decision Flow Chart

```
User enters URL
    ↓
├─→ Is domain in trusted whitelist?
│   ✅ YES → LEGITIMATE (0% risk) ✅
│   ❌ NO  → Continue to Tier 2
│
├─→ Is URL flagged by Google Safe Browsing?
│   ✅ YES → PHISHING (99% risk) 🚫
│   ❌ NO  → Continue to Tier 3
│
└─→ Run ML Model Ensemble
    ├─→ Probability < 35%? → LEGITIMATE (✅)
    ├─→ Probability 35-70%? → SUSPICIOUS (⚠️)
    └─→ Probability > 70%? → PHISHING (🚫)
```

---

## 📈 Real-World Examples

### Example 1: Your College Website
```
URL: https://www.velalarengg.ac.in/
1️⃣ Whitelist check: NOT in trusted list → Continue
2️⃣ Google Safe Browsing: NOT flagged → Continue
3️⃣ ML Model: 1.8% phishing probability → LEGITIMATE ✅
Display: ✅ LEGITIMATE URL | 1.8% Phishing Risk
```

### Example 2: Fake PayPal Phishing
```
URL: https://paypa1-secure-login.xyz/verify
1️⃣ Whitelist check: NOT in trusted list → Continue
2️⃣ Google Safe Browsing: FLAGGED as malicious → PHISHING 🚫
Display: 🚫 PHISHING URL | 99.0% Phishing Risk
```

### Example 3: Suspicious Bank Login
```
URL: http://bank-urgent-verify.net/account
1️⃣ Whitelist check: NOT in trusted list → Continue
2️⃣ Google Safe Browsing: NOT flagged → Continue
3️⃣ ML Model: 78% phishing probability → PHISHING 🚫
Display: 🚫 PHISHING URL | 78.0% Phishing Risk
```

---

## 🎛️ Threshold Configuration

Located in `/backend/app.py`:

```python
PHISHING_THRESHOLD = 0.70      # 70% - High risk
SUSPICIOUS_THRESHOLD = 0.35    # 35% - Medium risk
# Below 35% = Legitimate
```

To adjust thresholds:
1. Edit `backend/app.py` (Line ~64)
2. Change `PHISHING_THRESHOLD` and `SUSPICIOUS_THRESHOLD`
3. Restart backend

---

## ✨ Key Takeaways

| Detection Method | Output | Confidence |
|---|---|---|
| **Trusted Whitelist** | LEGITIMATE | 100% (pre-approved) |
| **Google Safe Browsing** | PHISHING | ~99% (Google's database) |
| **ML Ensemble** | Varies | ~85-95% (ML model accuracy) |

**Remember**: 
- **Low % phishing probability** = Safe ✅
- **High % phishing probability** = Risky 🚫

---

## 🚀 Next Steps

To test the system:

1. **Try safe URLs**: google.com, github.com, facebook.com
   - Expected: ✅ LEGITIMATE with 0-5% risk

2. **Try suspicious URLs**: paypa1-secure.xyz, amazon-verify.ru
   - Expected: 🚫 PHISHING with high risk

3. **Try real-world URLs**: Your college, company, bank
   - Expected: ✅ LEGITIMATE if trusted, varies otherwise

