import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, roc_auc_score)
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier

os.chdir(os.path.dirname(os.path.abspath(__file__)))

def load_cleaned_data(filepath="data/cleaned_data.csv"):
    """Load the cleaned dataset"""
    print("Loading cleaned data...")
    data = pd.read_csv(filepath)
    
    y = data['Label']
    X = data.drop(columns=['Label'])
    
    print(f"  X shape: {X.shape}")
    print(f"  Class balance: {y.value_counts().to_dict()}")
    return X, y


def balance_data(X, y):
    """Handle class imbalance using SMOTE"""
    print("\nApplying SMOTE to balance classes...")
    smote = SMOTE(random_state=42)
    X_balanced, y_balanced = smote.fit_resample(X, y)
    print(f"  After SMOTE: {pd.Series(y_balanced).value_counts().to_dict()}")
    return X_balanced, y_balanced


def train(X, y):
    """Train Random Forest and XGBoost classifiers"""

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # ── Random Forest ─────────────────────────────────────────────────────────
    print("\nTraining Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train_scaled, y_train)
    print("  Random Forest complete.")

    # ── XGBoost ───────────────────────────────────────────────────────────────
    print("\nTraining XGBoost...")
    xgb_model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=1,
        random_state=42,
        n_jobs=-1,
        eval_metric='logloss',
        verbosity=0
    )
    xgb_model.fit(X_train_scaled, y_train)
    print("  XGBoost complete.")

    return rf_model, xgb_model, scaler, X_test_scaled, y_test, X_train.columns.tolist()

def evaluate(model, X_test, y_test):
    """Evaluate model performance"""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    print("\n========== Model Evaluation ==========")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC  : {roc_auc_score(y_test, y_prob):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=['BENIGN', 'ATTACK']))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    return y_pred, y_prob


def get_feature_importance(model, feature_names, top_n=10):
    """Extract top N most important features"""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]
    
    print(f"\nTop {top_n} Important Features:")
    for rank, idx in enumerate(indices, 1):
        print(f"  {rank:>2}. {feature_names[idx]:<35} {importances[idx]:.4f}")
    
    return [(feature_names[i], importances[i]) for i in indices]


def save_artifacts(rf_model, xgb_model, scaler, feature_names, output_dir="models/"):
    """Save both models, scaler, and feature list"""
    os.makedirs(output_dir, exist_ok=True)

    joblib.dump(rf_model,      os.path.join(output_dir, "rf_model.pkl"))
    joblib.dump(xgb_model,     os.path.join(output_dir, "xgb_model.pkl"))
    joblib.dump(scaler,        os.path.join(output_dir, "scaler.pkl"))
    joblib.dump(feature_names, os.path.join(output_dir, "feature_names.pkl"))

    print(f"\nArtifacts saved to {output_dir}")
    print("  rf_model.pkl")
    print("  xgb_model.pkl")
    print("  scaler.pkl")
    print("  feature_names.pkl")

if __name__ == "__main__":
    X, y                                                   = load_cleaned_data()
    X_bal, y_bal                                           = balance_data(X, y)
    rf_model, xgb_model, scaler, X_test, y_test, features = train(X_bal, y_bal)

    print("\n===== Random Forest =====")
    evaluate(rf_model, X_test, y_test)
    get_feature_importance(rf_model, features)

    print("\n===== XGBoost =====")
    evaluate(xgb_model, X_test, y_test)
    get_feature_importance(xgb_model, features)

    save_artifacts(rf_model, xgb_model, scaler, features)