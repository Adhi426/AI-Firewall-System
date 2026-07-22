"""
Loads the trained model and exposes predict(features: dict) -> dict.

Imported directly by the backend (no network hop needed).
"""
import os
import joblib
import numpy as np

HERE = os.path.dirname(__file__)
MODEL_DIR = os.path.join(HERE, "saved_model")

_model = None
_scaler = None
_features = None


def _load():
    global _model, _scaler, _features
    if _model is None:
        model_path = os.path.join(MODEL_DIR, "model.joblib")
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                "No trained model found. Run `python train.py` inside ai-engine/ first."
            )
        _model = joblib.load(model_path)
        _scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
        _features = joblib.load(os.path.join(MODEL_DIR, "features.joblib"))
    return _model, _scaler, _features


PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}


def predict(flow: dict) -> dict:
    """
    flow: dict with keys matching ai-engine feature names (protocol may be
    given as a string "TCP"/"UDP"/"ICMP" or already numeric 0/1/2).

    Returns: { "label": "benign"|"malicious", "confidence": float }
    """
    model, scaler, features = _load()

    row = []
    for f in features:
        val = flow.get(f, 0)
        if f == "protocol" and isinstance(val, str):
            val = PROTOCOL_MAP.get(val.upper(), 0)
        row.append(float(val))

    X = np.array([row])
    X_scaled = scaler.transform(X)
    proba = model.predict_proba(X_scaled)[0]
    malicious_confidence = float(proba[1])
    label = "malicious" if malicious_confidence >= 0.5 else "benign"

    return {"label": label, "confidence": round(malicious_confidence, 4)}


if __name__ == "__main__":
    # quick smoke test
    sample_benign = {
        "duration_ms": 800, "packet_count": 40, "byte_count": 20000,
        "packets_per_sec": 50, "avg_packet_size": 500, "src_port": 51000,
        "dst_port": 443, "protocol": "TCP", "syn_ratio": 0.05,
        "unique_ports_touched": 1,
    }
    sample_scan = {
        "duration_ms": 100, "packet_count": 4, "byte_count": 240,
        "packets_per_sec": 40, "avg_packet_size": 60, "src_port": 51000,
        "dst_port": 22, "protocol": "TCP", "syn_ratio": 0.95,
        "unique_ports_touched": 300,
    }
    print("benign sample  ->", predict(sample_benign))
    print("scan sample    ->", predict(sample_scan))
