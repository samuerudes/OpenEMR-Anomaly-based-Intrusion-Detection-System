import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from imblearn.over_sampling import SMOTE
import joblib
import os

DATASET_PATH = os.path.expanduser('~/ids_system/dataset/combined_dataset.csv')
MODEL_DIR    = os.path.join(os.path.dirname(__file__), 'model')
os.makedirs(MODEL_DIR, exist_ok=True)

DROP_COLS = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
             'label', 'confidence', 'attack_type', 'severity', 'timestamp']

def train():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)
    print(f"Total samples: {len(df)}")
    print(df['label'].value_counts())

    feature_cols = [c for c in df.columns if c not in DROP_COLS]
    X = df[feature_cols].fillna(0)
    y = (df['label'] == 'attack').astype(int)

    counts = y.value_counts()
    if len(counts) < 2 or counts.min() < 2:
        print(f"ERROR: Class distribution too small: {counts.to_dict()}")
        return

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, random_state=42, stratify=y)

    print("Applying SMOTE...")
    smote = SMOTE(random_state=42)
    X_sm, y_sm = smote.fit_resample(X_train, y_train)
    print(f"After SMOTE — Normal: {(y_sm==0).sum()}, Attack: {(y_sm==1).sum()}")

    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_sm, y_sm)

    y_pred = rf.predict(X_test)
    cm      = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr     = fp / (fp + tn + 1e-9)

    print("\n=== Random Forest Results ===")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"F1-Score : {f1_score(y_test, y_pred):.4f}")
    print(f"FPR      : {fpr:.4f}")

    joblib.dump(rf,           os.path.join(MODEL_DIR, 'rf_model.pkl'))
    joblib.dump(scaler,       os.path.join(MODEL_DIR, 'scaler.pkl'))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, 'features.pkl'))
    print(f"\nModel saved to {MODEL_DIR}/")

if __name__ == '__main__':
    train()
