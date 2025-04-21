from flask import Flask, jsonify, request, render_template, redirect, url_for, session
import numpy as np
import sqlite3
import pickle
import warnings
import requests
from convert import convertion
from feature import FeatureExtraction

import os
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

with open("gbc.pkl", "rb") as file:
    gbc = pickle.load(file)

# Firebase configuration
# firebaseConfig = {
#     "apiKey": "AIzaSyCbS0fWLY65cJlzUKCcpJH2uNddhBho1rM",
#     "authDomain": "phish-detect.firebaseapp.com",
#     "projectId": "phish-detect",
#     "storageBucket": "phish-detect.firebasestorage.app",
#     "messagingSenderId": "1031544679518",
#     "appId": "1:1031544679518:web:8efe83d91c6724396cd8cf",
#     "measurementId": "G-7FB1SMPKKD",
#     "databaseURL": "https://phish-detect-default-rtdb.firebaseio.com/"
# }

# firebase = pyrebase.initialize_app(firebaseConfig)
# auth = firebase.auth()

# # Database setup
# def init_db():
#     conn = sqlite3.connect("phishing_urls.db")
#     cursor = conn.cursor()
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS phishing_urls (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             url TEXT NOT NULL UNIQUE,
#             detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#         )
#     ''')
#     conn.commit()
#     conn.close()

# init_db()

# Routes
@app.route("/")
def home():
    phishing_url = request.args.get("phishing_url")
    # user = session.get("user")
    # conn = sqlite3.connect("phishing_urls.db")
    # cursor = conn.cursor()
    # cursor.execute("SELECT DISTINCT url, detected_at FROM phishing_urls ORDER BY detected_at DESC")
    # urls = cursor.fetchall()
    # conn.close()
    return render_template("index.html", phishing_url=phishing_url)

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if request.method == "POST":
        url = request.form["name"]
        print("URL:", url)  
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()  
        except requests.exceptions.RequestException as e:
            print(f"Error checking URL: {e}")
            return render_template(
                "index.html",
                error="The website does not exist or is unreachable. Please check the URL and try again.",
                user=session.get("user")
            )
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        print("Extracted Features:", x) 
        y_pred = gbc.predict(x)[0]
        y_proba = gbc.predict_proba(x)
        print("Prediction:", y_pred) 
        print("Probabilities (Safe, Malicious):", y_proba) 

        y_pro_phishing = y_proba[0, 0]
        y_pro_non_phishing = y_proba[0, 1]

        threshold = 0.5  
        if y_pro_non_phishing > threshold:
            y_pred = 1  # Safe
        else:
            y_pred = -1  # Malicious

        if y_pred == 1:
            pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing * 100)
            xx = y_pro_non_phishing
            name = convertion(url, int(y_pred))
            # conn = sqlite3.connect("phishing_urls.db")
            # cursor = conn.cursor()
            # cursor.execute("INSERT INTO phishing_urls (url) VALUES (?)", (url,))
            # conn.commit()
            # conn.close()
        else:
            xx = y_pro_phishing
            name = convertion(url, int(y_pred))
        prediction_text = "Safe" if y_pred == 1 else "Malicious"
        return render_template(
            "index.html",
            name=name, 
            xx=xx,
            url=url,
            prediction_text=prediction_text,
            y_pro_phishing=y_pro_phishing,
            y_pro_non_phishing=y_pro_non_phishing,
            # user=session.get("user")
        )
@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    obj = FeatureExtraction(url)
    x = np.array(obj.getFeaturesList()).reshape(1, 30)
    y_pred = gbc.predict(x)[0]

    # if y_pred == -1:
    #     try:
    #         conn = sqlite3.connect("phishing_urls.db")
    #         cursor = conn.cursor()
    #         cursor.execute("INSERT INTO phishing_urls (url) VALUES (?)", (url,))
    #         conn.commit()
    #     except sqlite3.IntegrityError:
    #         print(f"Duplicate URL detected: {url}")
    #     finally:
    #         conn.close()

    return jsonify({"phishing": bool(y_pred == -1)})


if __name__ == "__main__":
    app.run(debug=True)