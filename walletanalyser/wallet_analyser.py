import requests
import pandas as pd
import time
import json
import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
PHISHING_CSV = "./transactions.csv"

app = Flask(__name__)

# Load known phishing addresses from CSV
def load_phishing_addresses():
    df = pd.read_csv(PHISHING_CSV)
    to_addresses = df["To"].dropna().str.lower().unique()
    from_addresses = df["From"].dropna().str.lower().unique()
    return set(to_addresses).union(from_addresses)

KNOWN_PHISHING_ADDRESSES = load_phishing_addresses()

# Etherscan API helpers
def get_transactions(address):
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=asc&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    return response.json().get("result", [])

def get_internal_transactions(address):
    url = f"https://api.etherscan.io/api?module=account&action=txlistinternal&address={address}&sort=asc&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    return response.json().get("result", [])

def get_erc20_transfers(address):
    url = f"https://api.etherscan.io/api?module=account&action=tokentx&address={address}&sort=asc&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    return response.json().get("result", [])

# Heuristics
def detect_delegatecall(transactions):
    return any("delegatecall" in tx.get("input", "").lower() for tx in transactions)

def detect_gasless_transactions(transactions):
    return any(tx.get("gasPrice") == "0" for tx in transactions)

def detect_proxies(transactions):
    return any("proxy" in tx.get("input", "").lower() for tx in transactions)

def detect_balance_draining(transactions):
    return sum(int(tx.get("value", "0")) for tx in transactions) > 10**18  # > 1 ETH

def detect_multisend(transactions):
    return any("multisend" in tx.get("input", "").lower() for tx in transactions)

def detect_phishing_address(address):
    return address.lower() in KNOWN_PHISHING_ADDRESSES

def detect_interactions_with_phishing(transactions):
    return any(tx.get("to", "").lower() in KNOWN_PHISHING_ADDRESSES or tx.get("from", "").lower() in KNOWN_PHISHING_ADDRESSES for tx in transactions)

def analyze_wallet(address):
    address = address.lower()
    print(f"Analyzing wallet: {address}")
    transactions = get_transactions(address)
    internal_txs = get_internal_transactions(address)
    erc20_txs = get_erc20_transfers(address)

    if not transactions:
        return {"error": "No transactions found."}

    analysis = {
        "address": address,
        "transaction_count": len(transactions),
        "interacted_with_phishing": detect_interactions_with_phishing(transactions),
        "delegatecall_detected": detect_delegatecall(transactions),
        "gasless_transactions": detect_gasless_transactions(transactions),
        "proxy_behavior": detect_proxies(transactions),
        "balance_draining": detect_balance_draining(transactions),
        "multisend_behavior": detect_multisend(transactions),
        "phishing_tag": detect_phishing_address(address),
    }

    # Calculate risk score as a percentage
    total_parameters = len([key for key in analysis if isinstance(analysis[key], bool)])
    true_parameters = sum(1 for key, value in analysis.items() if isinstance(value, bool) and value)
    risk_score = (true_parameters / total_parameters) * 100  # Percentage

    return {"risk_score": risk_score, "wallet_analysis": analysis}

# Route to handle wallet analysis
@app.route("/analyze_wallet", methods=["POST"])
def analyze_wallet_route():
    data = request.get_json()
    address = data.get("address")
    if not address:
        return jsonify({"error": "Address is required."}), 400
    
    result = analyze_wallet(address)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
