"""
Trains the malicious-traffic classifier and saves the model + scaler.

Usage:
    python train.py
"""
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score

from data.generate_data import generate, FEATURES

HERE = os.path.dirname(__file__)
MODEL_DIR = os.path.join(HERE, "saved_model")


def main():
    print("Generating synthetic training data...")
    df = generate(n_benign=6000, n_each_attack=1500)

    X = df[FEATURES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    y_proba = clf.predict_proba(X_test_scaled)[:, 1]

    print("\n=== Evaluation on held-out test set ===")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))
    print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.4f}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(MODEL_DIR, "model.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(FEATURES, os.path.join(MODEL_DIR, "features.joblib"))
    print(f"\nSaved model + scaler to {MODEL_DIR}/")


if __name__ == "__main__":
    main()
