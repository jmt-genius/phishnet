from flask import Flask, request, jsonify
import tensorflow
from keras.models import load_model

import numpy as np
import re
import string

app = Flask(__name__)

model = load_model("URL_RFC.h5")  

MAX_LEN = 200  #
CHARSET = string.ascii_lowercase + string.digits + ":/.?&=%-_"  

char_to_int = {char: i + 1 for i, char in enumerate(CHARSET)}  # 0 is padding

def preprocess_url(url):
    url = url.lower()
    url = re.sub(r"[^a-z0-9:/?&=%.@_-]", "", url)  
    encoded = [char_to_int.get(c, 0) for c in url]
    padded = encoded[:MAX_LEN] + [0] * (MAX_LEN - len(encoded))
    return np.array([padded])

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing 'url' in JSON"}), 400

    try:
        X = preprocess_url(url)
        prediction = model.predict(X)[0][0]
        label = "malicious" if prediction > 0.5 else "safe"
        return jsonify({
            "url": url,
            "prediction": float(prediction),
            "label": label
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def home():
    return "Malicious URL detection model is running."

if __name__ == "__main__":
    app.run(debug=True)
