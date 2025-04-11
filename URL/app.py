import pickle
import pandas as pd
import re
import urllib.parse
from flask import Flask, request, jsonify

# Initialize Flask app
app = Flask(__name__)

# Load the saved model and vectorizer
with open('url_rfc_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Feature extraction function
def extract_url_features(url):
    features = {}

    # Extract hostname length
    hostname = urllib.parse.urlparse(url).hostname
    features['hostname_length'] = len(hostname) if hostname else 0

    # Extract path length
    path = urllib.parse.urlparse(url).path
    features['path_length'] = len(path)

    # Extract file descriptor length (if applicable)
    fd_length = len(path.split('/')[-1]) if path.split('/') else 0
    features['fd_length'] = fd_length

    # Count occurrences of specific characters
    features['count-'] = url.count('-')
    features['count@'] = url.count('@')
    features['count?'] = url.count('?')
    features['count%'] = url.count('%')
    features['count.'] = url.count('.')
    features['count='] = url.count('=')
    features['count-http'] = url.count('http')
    features['count-https'] = url.count('https')
    features['count-www'] = url.count('www')

    # Count letters in the URL (alphabetic characters only)
    features['count-letters'] = len(re.findall(r'[a-zA-Z]', url))

    # Count directories in the URL path
    features['count_dir'] = path.count('/')

    # Check if the URL contains an IP address
    features['use_of_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0

    # Debugging: print the features and check the total number
    print("Extracted Features:", features)
    print("Number of Features:", len(features))

    # Return features as a pandas DataFrame with the exact feature names
    return pd.DataFrame([features])

# Preprocess URL and extract features
def preprocess_url(url):
    return extract_url_features(url)

# Define the '/predict' route
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get the URL from the request
        data = request.get_json()
        url = data['url']

        # Preprocess the URL and extract features
        processed_url = preprocess_url(url)

        # Make prediction using the loaded model
        prediction = model.predict(processed_url)

        # Return prediction result
        if prediction[0] == 1:
            return jsonify({'prediction': 'malicious'})
        else:
            return jsonify({'prediction': 'not malicious'})

    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    # Specify port number as 5002
    app.run(debug=True, port=5002)
