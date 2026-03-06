import streamlit as st
import joblib
import re
import matplotlib.pyplot as plt
from wordcloud import WordCloud

# -----------------------------
# Load model and vectorizer
# -----------------------------
model = joblib.load("C:\\Users\\bhoom\\OneDrive\\Desktop\\email_phish\\email_phishing_model.pkl")
vectorizer = joblib.load("C:\\Users\\bhoom\\OneDrive\\Desktop\\email_phish\\tfidf_vectorizer.pkl")

# -----------------------------
# Styling
# -----------------------------
st.set_page_config(page_title="Phishing Email Detector", layout="wide")
st.markdown("""
    <style>
        .stApp {background-color: #001f3f; color: white;}
        .stTextArea textarea {background-color: #003366; color: white;}
        .stButton button {background-color: #0074D9; color: white; font-weight:bold;}
        .stHeader {color: #FFDC00;}
    </style>
""", unsafe_allow_html=True)

# -----------------------------
# Email Cleaning Function
# -----------------------------
import re
import nltk
from nltk.corpus import stopwords

nltk.download('stopwords')
stop_words = set(stopwords.words('english'))

def clean_email(text):
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', '', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'[^\w\s]', '', text)
    words = [w for w in text.split() if w not in stop_words]
    return " ".join(words)
# -----------------------------
# Page Layout
# -----------------------------
st.title("Phishing Email Detector")
st.subheader("Paste your email below to detect if it's phishing")

email_input = st.text_area("Paste Email Here", height=200)

if st.button("Check Email"):
    if not email_input.strip():
        st.warning("Please paste an email text first!")
    else:
        cleaned = clean_email(email_input)
        features = vectorizer.transform([cleaned])
        pred_proba = model.predict_proba(features)[0]
        pred = model.predict(features)[0]

        # -----------------------------
        # Prediction Result
        # -----------------------------
        if pred == 1:
            st.error(f"Phishing!! (Probability: {pred_proba[1]*100:.2f}%)")
        else:
            st.success(f"Legitimate. (Probability: {pred_proba[0]*100:.2f}%)")

        # -----------------------------
        # Pie Chart
        # -----------------------------
        # -----------------------------
        # Pie Chart (Exact 400x400 px)
        # -----------------------------
        import io
        import matplotlib.pyplot as plt

        # Create pie chart
        fig, ax = plt.subplots(figsize=(4, 4), dpi=100)  # 4x4 inches × 100 dpi = 400px
        ax.pie(
            pred_proba,
            labels=["Legitimate", "Phishing"],
            autopct='%1.1f%%',
            colors=["#2ECC40", "#FF4136"],
            startangle=90
        )
        ax.axis('equal')  # Equal aspect ratio

        # Save figure to a bytes buffer and display as an image
        buf = io.BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight', transparent=True)
        buf.seek(0)
        st.image(buf, width=400)  # display at exact 400px width
        plt.close(fig)  # close figure to free memory

        # -----------------------------
        # Highlight suspicious words
        # -----------------------------
        suspicious_words = ['verify', 'login', 'password', 'bank', 'update', 'click', 'account', 'secure']
        words = email_input.split()
        highlighted_email = ""
        for w in words:
            if any(sw in w.lower() for sw in suspicious_words):
                highlighted_email += f"<span style='background-color: #FF4136; color:white'>{w}</span> "
            else:
                highlighted_email += w + " "

        st.markdown("### ⚠️ Suspicious Words Highlighted:")
        st.markdown(highlighted_email, unsafe_allow_html=True)