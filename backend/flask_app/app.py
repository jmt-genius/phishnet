from flask import Flask, request, jsonify
import requests
import logging
import uuid

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NODE_SERVICE_URL = "http://localhost:3000/midnight-sdk"

@app.route('/report-scam', methods=['POST'])
def report_scam():
    logger.info("Received scam report request")
    data = request.json

    # Validate incoming JSON
    required_keys = ["contractAddress", "riskLevel", "vulnerabilities", "reporter"]
    missing_keys = [key for key in required_keys if key not in data]
    
    if missing_keys:
        logger.error(f"Missing required keys: {missing_keys}")
        return jsonify({"error": f"Missing required fields: {', '.join(missing_keys)}"}), 400

    try:
        logger.info(f"Forwarding data to Node.js service: {data}")
        # Forward data to Node.js service for Midnight SDK processing
        response = requests.post(NODE_SERVICE_URL, json=data)

        if response.status_code == 200:
            result = response.json()
            logger.info(f"Successfully submitted report: {result}")
            return jsonify({
                "status": result["status"],
                "hash": result["hash"],
                "message": "Your scam report has been privately submitted!"
            }), 200
        else:
            logger.error(f"Node.js service returned error: {response.text}")
            return jsonify({"error": "Failed to submit report to processing service"}), 500

    except requests.RequestException as e:
        logger.error(f"Failed to connect to Node.js service: {str(e)}")
        return jsonify({"error": "Connection to processing service failed"}), 503
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

# Add a route for health checking
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    logger.info("Starting Flask server on port 5000")
    app.run(port=5000, debug=True)