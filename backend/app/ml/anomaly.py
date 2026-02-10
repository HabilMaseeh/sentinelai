from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURE_NAMES = [
    "hour",
    "hour_sin",
    "hour_cos",
    "failed_attempts_2m",
    "success_attempts_2m",
    "event_rate_2m",
    "unique_users_5m",
    "unique_ips_5m",
    "user_event_rate_1h",
    "user_failed_1h",
    "user_success_1h",
    "user_unique_ips_1h",
    "user_event_rate_24h",
    "user_failed_ratio_24h",
    "ip_is_private",
    "ip_is_reserved",
    "ip_is_global",
]

MODEL_PATH = Path(__file__).resolve().parent / "anomaly_model.joblib"


class AnomalyModel:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.trained = False
        self.model_version = None
        self.last_trained_at = None
        self.last_train_samples = 0
        self.load()

    def vectorize(self, feature_dicts):
        return np.array([
            [float(d.get(name, 0) or 0) for name in FEATURE_NAMES]
            for d in feature_dicts
        ])

    def train(self, feature_dicts: list[dict]):
        if not feature_dicts:
            return
        X = self.vectorize(feature_dicts)
        self.model.fit(X)
        now = datetime.now(timezone.utc).isoformat()
        self.trained = True
        self.model_version = now
        self.last_trained_at = now
        self.last_train_samples = len(feature_dicts)
        self.save()

    def predict(self, feature_dict: dict) -> tuple[bool, float]:
        X = self.vectorize([feature_dict])
        pred = self.model.predict(X)[0] == -1
        score = float(self.model.decision_function(X)[0])
        return pred, score

    def save(self):
        data = {
            "model": self.model,
            "trained": self.trained,
            "model_version": self.model_version,
            "last_trained_at": self.last_trained_at,
            "last_train_samples": self.last_train_samples,
            "feature_names": FEATURE_NAMES,
        }
        joblib.dump(data, MODEL_PATH)

    def load(self):
        if not MODEL_PATH.exists():
            return
        data = joblib.load(MODEL_PATH)
        self.model = data.get("model", self.model)
        self.trained = bool(data.get("trained", False))
        self.model_version = data.get("model_version", None)
        self.last_trained_at = data.get("last_trained_at", None)
        self.last_train_samples = int(data.get("last_train_samples", 0) or 0)


anomaly_model = AnomalyModel()
