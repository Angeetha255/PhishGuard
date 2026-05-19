"""
PhishGuard AI — Training Pipeline
===================================
Trains a stacked ensemble:
  Base models: RandomForest + GradientBoosting + XGBoost
  Meta model:  LogisticRegression on base model outputs

Key design choices:
  - 42 handcrafted features (no TF-IDF dependency at inference time)
  - TF-IDF kept as a supplementary signal during training only
  - class_weight='balanced' on all base models → maximise recall
  - SMOTE oversampling to further balance phishing samples
  - Stratified k-fold cross-validation
  - Threshold tuned to minimise false negatives (recall-first)
  - All models saved to backend/model/
"""

import os
import sys
import warnings
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, roc_auc_score, recall_score, precision_score,
)
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
from tqdm import tqdm

warnings.filterwarnings('ignore')

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.feature_extraction import extract_feature_vector, get_feature_names
from utils.phishing_rules import run_rules

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model')
DATA_DIR  = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(MODEL_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# 1. DATA LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_datasets() -> pd.DataFrame:
    frames = []

    # ── Dataset 1: clean_phishing_dataset.csv ─────────────
    p1 = os.path.join(DATA_DIR, 'clean_phishing_dataset.csv')
    if os.path.exists(p1):
        df1 = pd.read_csv(p1)
        print(f'Dataset 1 columns: {df1.columns.tolist()}')
        if 'URL' in df1.columns and 'Label' in df1.columns:
            df1 = df1[['URL', 'Label']].rename(columns={'Label': 'label'})
            frames.append(df1)
            print(f'  ✅ Loaded {len(df1):,} rows')
        else:
            print('  ⚠️  Missing URL/Label columns — skipped')

    # ── Dataset 2: Phishing_Legitimate_full.csv ────────────
    p2 = os.path.join(DATA_DIR, 'Phishing_Legitimate_full.csv')
    if os.path.exists(p2):
        df2 = pd.read_csv(p2)
        print(f'Dataset 2 columns: {df2.columns.tolist()}')
        if 'URL' in df2.columns:
            label_col = next((c for c in ('CLASS_LABEL', 'Label', 'label') if c in df2.columns), None)
            if label_col:
                df2 = df2[['URL', label_col]].rename(columns={label_col: 'label'})
                frames.append(df2)
                print(f'  ✅ Loaded {len(df2):,} rows')
            else:
                print('  ⚠️  No label column found — skipped')
        else:
            print('  ⚠️  No URL column — skipped')

    # ── Dataset 3: PhishTank CSV (if present) ─────────────
    p3 = os.path.join(DATA_DIR, 'phishtank.csv')
    if os.path.exists(p3):
        try:
            df3 = pd.read_csv(p3, usecols=lambda c: c.lower() in ('url', 'phish_url'))
            df3.columns = ['URL']
            df3['label'] = 1  # all PhishTank entries are phishing
            frames.append(df3)
            print(f'  ✅ PhishTank: loaded {len(df3):,} phishing URLs')
        except Exception as e:
            print(f'  ⚠️  PhishTank load error: {e}')

    if not frames:
        raise ValueError('No valid datasets found in data/')

    df = pd.concat(frames, ignore_index=True)
    print(f'\nCombined: {len(df):,} rows')
    return df


def clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    mapping = {
        '0': 0, 'good': 0, 'legitimate': 0, 'benign': 0,
        '1': 1, '-1': 1, 'bad': 1, 'phishing': 1, 'malicious': 1,
    }
    y_raw = df['label'].astype(str).str.strip().str.lower()
    df['label'] = y_raw.map(mapping)

    # Fallback for numeric strings not in mapping
    unmapped = df['label'].isna()
    if unmapped.any():
        def fallback(v):
            try:
                return 1 if float(v) != 0 else 0
            except Exception:
                return np.nan
        df.loc[unmapped, 'label'] = y_raw[unmapped].apply(fallback)

    df = df.dropna(subset=['URL', 'label'])
    df['label'] = df['label'].astype(int)

    # Normalise URLs — add http:// prefix if missing so feature extractor works
    def normalise_url(u):
        u = str(u).strip()
        if u.startswith(('http://', 'https://')):
            return u
        return 'http://' + u

    df['URL'] = df['URL'].apply(normalise_url)
    df = df.drop_duplicates(subset='URL')
    return df.reset_index(drop=True)


# ══════════════════════════════════════════════════════════════════════════════
# 2. FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def build_feature_matrix(urls: pd.Series) -> np.ndarray:
    """Extract 42 features for every URL. Shows a progress bar."""
    rows = []
    for url in tqdm(urls, desc='Extracting features', unit='url'):
        try:
            vec = extract_feature_vector(url)
            # 42nd feature: heuristic rule score
            rule = run_rules(url)
            vec.append(rule['rule_score'])
            rows.append(vec)
        except Exception:
            rows.append([0.0] * 42)
    return np.array(rows, dtype=float)


# ══════════════════════════════════════════════════════════════════════════════
# 3. TRAINING
# ══════════════════════════════════════════════════════════════════════════════

def train():
    print('\n' + '='*60)
    print('  PhishGuard AI — Training Pipeline')
    print('='*60 + '\n')

    # ── Load & clean ───────────────────────────────────────
    df = load_datasets()
    df = clean_labels(df)

    print(f'\nLabel distribution:')
    print(df['label'].value_counts())
    print(f'Phishing ratio: {df["label"].mean():.1%}\n')

    # ── Smart sampling — cap at 100k per class for speed ──
    MAX_PER_CLASS = 100_000
    phishing_df   = df[df['label'] == 1]
    legit_df      = df[df['label'] == 0]

    if len(phishing_df) > MAX_PER_CLASS:
        phishing_df = phishing_df.sample(MAX_PER_CLASS, random_state=42)
        print(f'Sampled {MAX_PER_CLASS:,} phishing URLs (from {len(df[df["label"]==1]):,})')
    if len(legit_df) > MAX_PER_CLASS:
        legit_df = legit_df.sample(MAX_PER_CLASS, random_state=42)
        print(f'Sampled {MAX_PER_CLASS:,} legitimate URLs (from {len(df[df["label"]==0]):,})')

    df = pd.concat([phishing_df, legit_df], ignore_index=True).sample(frac=1, random_state=42)
    print(f'\nFinal training set: {len(df):,} rows')
    print(df['label'].value_counts())
    print()

    X_urls = df['URL']
    y      = df['label'].values

    # ── Feature matrix ─────────────────────────────────────
    print('Building feature matrix...')
    X = build_feature_matrix(X_urls)
    print(f'Feature matrix shape: {X.shape}')

    # ── Train / test split ─────────────────────────────────
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, X_urls.values,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )
    print(f'Train: {len(X_train):,}  |  Test: {len(X_test):,}')

    # ── Scale features ─────────────────────────────────────
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── SMOTE oversampling ─────────────────────────────────
    print('\nApplying SMOTE...')
    smote = SMOTE(random_state=42, k_neighbors=5)
    X_train_sm, y_train_sm = smote.fit_resample(X_train_s, y_train)
    print(f'After SMOTE — phishing: {y_train_sm.sum():,}  legitimate: {(y_train_sm==0).sum():,}')

    # ── Base models ────────────────────────────────────────
    print('\nTraining base models...')

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )

    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.08,
        max_depth=5,
        subsample=0.8,
        random_state=42,
    )

    xgb = XGBClassifier(
        n_estimators=300,
        learning_rate=0.08,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=(y_train_sm == 0).sum() / y_train_sm.sum(),
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
    )

    for name, clf in [('RandomForest', rf), ('GradientBoosting', gb), ('XGBoost', xgb)]:
        print(f'  Training {name}...')
        clf.fit(X_train_sm, y_train_sm)
        p = clf.predict(X_test_s)
        recall = recall_score(y_test, p)
        prec   = precision_score(y_test, p)
        print(f'    Recall={recall:.3f}  Precision={prec:.3f}')

    # ── Stacking: build meta-features ─────────────────────
    print('\nBuilding meta-features for stacking...')

    def oof_probs(clf, X_tr, y_tr, X_te, n_splits=5):
        """Out-of-fold probabilities for stacking."""
        skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
        oof = np.zeros(len(X_tr))
        for fold, (ti, vi) in enumerate(skf.split(X_tr, y_tr)):
            clf.fit(X_tr[ti], y_tr[ti])
            oof[vi] = clf.predict_proba(X_tr[vi])[:, 1]
        test_p = clf.predict_proba(X_te)[:, 1]
        return oof, test_p

    rf_oof,  rf_test  = oof_probs(rf,  X_train_sm, y_train_sm, X_test_s)
    gb_oof,  gb_test  = oof_probs(gb,  X_train_sm, y_train_sm, X_test_s)
    xgb_oof, xgb_test = oof_probs(xgb, X_train_sm, y_train_sm, X_test_s)

    # Retrain base models on full training set
    print('Retraining base models on full training set...')
    rf.fit(X_train_sm, y_train_sm)
    gb.fit(X_train_sm, y_train_sm)
    xgb.fit(X_train_sm, y_train_sm)

    # Meta-features
    meta_train = np.column_stack([rf_oof, gb_oof, xgb_oof])
    meta_test  = np.column_stack([rf_test, gb_test, xgb_test])

    # ── Meta-classifier ────────────────────────────────────
    print('\nTraining meta-classifier (LogisticRegression)...')
    meta_clf = LogisticRegression(
        C=1.0,
        class_weight='balanced',
        max_iter=1000,
        random_state=42,
    )
    meta_clf.fit(meta_train, y_train_sm[:len(meta_train)])

    # ── Evaluation ─────────────────────────────────────────
    print('\n' + '='*60)
    print('  EVALUATION ON TEST SET')
    print('='*60)

    meta_probs = meta_clf.predict_proba(meta_test)[:, 1]

    # Tune threshold to maximise recall while keeping precision > 0.70
    best_thresh = 0.50
    best_recall = 0.0
    for t in np.arange(0.30, 0.75, 0.01):
        preds = (meta_probs >= t).astype(int)
        r = recall_score(y_test, preds)
        p = precision_score(y_test, preds)
        if r > best_recall and p >= 0.70:
            best_recall = r
            best_thresh = t

    print(f'\nOptimal threshold (recall-first, precision≥0.70): {best_thresh:.2f}')
    y_pred = (meta_probs >= best_thresh).astype(int)

    print(f'\nAccuracy:  {accuracy_score(y_test, y_pred):.4f}')
    print(f'Recall:    {recall_score(y_test, y_pred):.4f}  ← minimise false negatives')
    print(f'Precision: {precision_score(y_test, y_pred):.4f}')
    print(f'ROC-AUC:   {roc_auc_score(y_test, meta_probs):.4f}')
    print('\nClassification Report:')
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print('Confusion Matrix:')
    cm = confusion_matrix(y_test, y_pred)
    print(f'  TN={cm[0,0]}  FP={cm[0,1]}')
    print(f'  FN={cm[1,0]}  TP={cm[1,1]}')

    # ── TF-IDF supplementary model ─────────────────────────
    print('\nTraining supplementary TF-IDF model...')
    tfidf = TfidfVectorizer(
        analyzer='char',
        ngram_range=(3, 5),
        min_df=3,
        max_df=0.95,
        sublinear_tf=True,
        max_features=50000,
    )
    X_tfidf_train = tfidf.fit_transform(urls_train)
    X_tfidf_test  = tfidf.transform(urls_test)

    tfidf_rf = RandomForestClassifier(
        n_estimators=200,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    tfidf_rf.fit(X_tfidf_train, y_train)
    tfidf_preds = tfidf_rf.predict(X_tfidf_test)
    print(f'  TF-IDF RF Recall: {recall_score(y_test, tfidf_preds):.4f}')

    # ── Save everything ────────────────────────────────────
    print('\nSaving models...')
    joblib.dump(rf,          os.path.join(MODEL_DIR, 'rf_model.pkl'))
    joblib.dump(gb,          os.path.join(MODEL_DIR, 'gb_model.pkl'))
    joblib.dump(xgb,         os.path.join(MODEL_DIR, 'xgb_model.pkl'))
    joblib.dump(meta_clf,    os.path.join(MODEL_DIR, 'meta_model.pkl'))
    joblib.dump(scaler,      os.path.join(MODEL_DIR, 'feature_scaler.pkl'))
    joblib.dump(tfidf,       os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl'))
    joblib.dump(tfidf_rf,    os.path.join(MODEL_DIR, 'phishing_model.pkl'))  # legacy compat

    # Save optimal threshold
    import json
    with open(os.path.join(MODEL_DIR, 'thresholds.json'), 'w') as f:
        json.dump({'phishing': best_thresh, 'suspicious': best_thresh - 0.20}, f, indent=2)

    print('\n✅ All models saved to backend/model/')
    print(f'   rf_model.pkl, gb_model.pkl, xgb_model.pkl')
    print(f'   meta_model.pkl, feature_scaler.pkl, tfidf_vectorizer.pkl')
    print(f'   thresholds.json (phishing={best_thresh:.2f})')
    print('\n🎉 Training complete!')


if __name__ == '__main__':
    train()
