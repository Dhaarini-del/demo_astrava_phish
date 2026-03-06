import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# Load model
model = joblib.load(r"C:\Users\ggowt\AppData\Local\Programs\Python\Python311\AlphaFem\url_phishing_model.pkl")

feature_names = model.feature_names_in_

# phishing keywords
phishing_words = [
    "verify",
    "login",
    "password",
    "account",
    "urgent",
    "bank",
    "suspend",
    "update",
    "confirm",
    "click"
]


# -----------------------------
# Extract URL
# -----------------------------
def extract_url(text):

    urls = re.findall(r'https?://[^\s]+', text)

    if urls:
        return urls[0]

    return None


# -----------------------------
# Extract URL Features
# -----------------------------
def extract_features(url):

    parsed = urlparse(url)

    features = {}

    features["id"] = 0
    features["NumDots"] = url.count(".")
    features["SubdomainLevel"] = parsed.netloc.count(".")
    features["PathLevel"] = parsed.path.count("/")
    features["UrlLength"] = len(url)
    features["NumDash"] = url.count("-")
    features["NumDashInHostname"] = parsed.netloc.count("-")
    features["AtSymbol"] = url.count("@")
    features["NumNumericChars"] = sum(c.isdigit() for c in url)
    features["NoHttps"] = 0 if "https" in url else 1

    for f in feature_names:
        if f not in features:
            features[f] = 0

    return pd.DataFrame([features])[feature_names]


# -----------------------------
# Predict Email
# -----------------------------
def predict_email(message):

    text = message.lower()

    # keyword score
    keyword_score = sum(word in text for word in phishing_words)

    url = extract_url(message)

    if url:

        df = extract_features(url)

        prediction = model.predict(df)[0]
        prob = model.predict_proba(df)[0]

        if prediction == 1:
            return "Phishing Email", prob[1]

    if keyword_score >= 2:
        return "Phishing Email", 0.85

    return "Safe Email", 0.90


# -----------------------------
# User Interface
# -----------------------------
print("\n==============================")
print("   Email Phishing Detector")
print("==============================")

while True:

    message = input("\nEnter email message (or type exit):\n")

    if message.lower() == "exit":
        break

    label, confidence = predict_email(message)

    print("\nResult:", label)
    print("Confidence Score:", round(confidence * 100, 2), "%")