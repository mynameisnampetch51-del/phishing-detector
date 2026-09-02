# Phishing Detector ML API

Backend for the ML layer of `phishing-detector`. The static site (GitHub Pages)
can only check URL-string patterns in-browser — it can't fetch an arbitrary
external page's HTML due to CORS. This API does that server-side: it fetches
the target URL, extracts the same features the trained model
(`../../phishing-ml-classifier/main.ipynb`) was trained on, and returns a
single verdict.

Weights/means/stds are read from `model_weights.json`, which is a
machine-generated copy of the array in `../ml-feature.js` (same model, no
retraining happens here — this service only scores).

Note: in the training data, `label == 1` means **legitimate**, `label == 0`
means **phishing**. The API inverts that for the response.

## Run locally

```bash
cd api
uv sync   # or: pip install fastapi "uvicorn[standard]" requests beautifulsoup4
uv run uvicorn main:app --reload --port 8000
```

## API

`POST /predict`

```json
{ "url": "https://example.com" }
```

Response:

```json
{ "isPhishing": false }
```

## Known limitations

- A handful of "derived" PhiUSIIL features (`CharContinuationRate`,
  `TLDLegitimateProb`, `URLCharProb`, `DomainTitleMatchScore`,
  `URLTitleMatchScore`) have no published exact formula — `features.py`
  implements reasonable approximations, documented inline. Predictions on
  live sites will be directionally right but won't perfectly match the
  notebook's held-out test accuracy.
- Sites that block simple `requests` fetches (bot detection, JS-only
  rendering) will score using URL-only features.
