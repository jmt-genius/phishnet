from flask import Flask, request, jsonify
from contract_analyser import analyze_smart_contract, generate_security_report, format_report_for_display
from dotenv import load_dotenv
import os
import logging

load_dotenv()

app = Flask(__name__)

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    address = data.get("address")
    if not address:
        return jsonify({"error": "Missing contract address"}), 400

    try:
        logging.debug(f"Analyzing contract: {address}")
        results = analyze_smart_contract(
            address,
            ETHERSCAN_API_KEY,
            GEMINI_API_KEY
        )

        report = generate_security_report(results["analysis_file"])
        formatted = format_report_for_display(report)

        return jsonify({
            "contract": results["contract_name"],
            "report_summary": report,
            "formatted_markdown": formatted
        })

    except Exception as e:
        logging.error(f"Error analyzing contract: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True, port=5001)
