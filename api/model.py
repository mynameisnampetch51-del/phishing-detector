import json
import math
from pathlib import Path

_WEIGHTS_PATH = Path(__file__).parent / "model_weights.json"
_weights = json.loads(_WEIGHTS_PATH.read_text())
INTERCEPT = _weights["intercept"]
FEATURES = _weights["features"]


def predict_proba(feature_values: dict) -> float:
    score = INTERCEPT
    for f in FEATURES:
        raw = feature_values.get(f["name"], f["mean"])
        scaled = (raw - f["mean"]) / f["std"]
        score += scaled * f["weight"]
    return 1 / (1 + math.exp(-score))
