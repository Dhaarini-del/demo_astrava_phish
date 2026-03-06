from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # <-- allow JS frontend to call this API

# Load model & scaler
model = joblib.load(r"C:\Users\bhoom\OneDrive\Desktop\AlphaFem1\AlphaFem\url_model_advanced.pkl")
scaler = joblib.load(r"C:\Users\bhoom\OneDrive\Desktop\AlphaFem1\AlphaFem\url_scaler.pkl")

# Feature extraction function (same as training)
def extract_features(url):
    features = {}
    features['length'] = len(url)
    features['dots'] = url.count('.')
    features['hyphens'] = url.count('-')
    features['at'] = url.count('@')
    features['https'] = 1 if url.startswith('https') else 0
    features['digits'] = sum(c.isdigit() for c in url)
    try:
        features['subdomains'] = len(urlparse(url).hostname.split('.')) - 2
    except:
        features['subdomains'] = 0
    return list(features.values())

@app.route("/scan_url", methods=["POST"])
def scan_url():
    data = request.json
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Extract features & scale
    features = extract_features(url)
    features_scaled = scaler.transform([features])

    # Predict
    pred = model.predict(features_scaled)[0]

    risk = 85 if pred == 1 else 10
    result = "phishing" if pred == 1 else "safe"

    return jsonify({"result": result, "risk": risk})

if __name__ == "__main__":
    app.run(debug=True)