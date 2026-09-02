from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from features import extract_content_features, extract_url_features
from model import predict_proba

app = FastAPI(title="Phishing Detector ML API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

REQUEST_TIMEOUT = 8
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class PredictRequest(BaseModel):
    url: str


class PredictResponse(BaseModel):
    isPhishing: bool


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    url = req.url if "://" in req.url else f"https://{req.url}"

    url_features, hostname, _tld = extract_url_features(url)
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")

    try:
        response = requests.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException:
        # Page unreachable: fall back to URL-only features (mean-imputed content features).
        proba_legit = predict_proba(url_features)
        return {"isPhishing": proba_legit < 0.5}

    redirect_hosts = [urlparse(r.url).hostname for r in response.history]
    redirect_hosts = [h for h in redirect_hosts if h]

    content_features = extract_content_features(
        response.text, str(response.url), hostname, redirect_hosts
    )

    all_features = {**url_features, **content_features}
    proba_legit = predict_proba(all_features)
    return {"isPhishing": proba_legit < 0.5}
