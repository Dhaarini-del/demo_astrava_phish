import pandas as pd
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Load dataset
data = pd.read_csv(r"C:\Users\bhoom\OneDrive\Desktop\AlphaFem1\AlphaFem\phishing_url_dataset.csv")[['URL', 'type']]
data = data.rename(columns={'URL':'url','type':'label'})

# Feature extraction
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
    return features

X = pd.DataFrame([extract_features(u) for u in data['url']])
y = data['label']

# Scale numeric features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Random Forest classifier (better than Naive Bayes here)
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# Accuracy
pred = model.predict(X_test)
from sklearn.metrics import accuracy_score
print("Accuracy:", accuracy_score(y_test, pred))

# Save model
joblib.dump(model, "url_model_advanced.pkl")
joblib.dump(scaler, "url_scaler.pkl")
print("Advanced model saved!")