from flask import Flask, render_template, request, jsonify
import pandas as pd
import requests
import socket
import whois
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score

app = Flask(__name__)

# LOAD DATASET
data = pd.read_csv("phishing_dataset.csv")
data.columns = data.columns.str.strip()

X = data.iloc[:,0]
y = data.iloc[:,1]

# TRAIN MODEL
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2)

model = RandomForestClassifier()
model.fit(X_train, y_train)

# MODEL METRICS
y_pred = model.predict(X_test)

accuracy = round(accuracy_score(y_test, y_pred)*100,2)
precision = round(precision_score(y_test, y_pred)*100,2)
recall = round(recall_score(y_test, y_pred)*100,2)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():

    url = request.json["url"]

    # Prediction
    url_vec = vectorizer.transform([url])
    result = model.predict(url_vec)[0]

    risk = 90 if result==1 else 10

    # IP Address
    try:
        ip = socket.gethostbyname(url.replace("https://","").replace("http://","").split("/")[0])
    except:
        ip = "Unknown"

    # Country
    try:
        country = requests.get(f"http://ip-api.com/json/{ip}").json()["country"]
    except:
        country = "Unknown"

    # Whois
    try:
        domain_info = whois.whois(url)
        origin = str(domain_info.creation_date)
    except:
        origin = "Unknown"

    description = f"{url} is a website analyzed by SecureNet AI. The system evaluates phishing risk using machine learning, domain reputation and URL structure patterns."

    return jsonify({
        "risk": risk,
        "ip": ip,
        "country": country,
        "origin": origin,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "description": description
    })


if __name__ == "__main__":
    app.run(debug=True)