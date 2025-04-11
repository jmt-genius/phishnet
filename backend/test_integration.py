#!/usr/bin/env python3
import requests
import json
import time
import logging
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# URLs
FLASK_URL = "http://localhost:5000/report-scam"
NODE_URL = "http://localhost:3000/midnight-sdk"
NODE_HEALTH_URL = "http://localhost:3000/health"

# Test data
test_data = {
    "contractAddress": f"0x{uuid.uuid4().hex[:12].upper()}",  # Generate a unique contract address
    "riskLevel": "High",
    "vulnerabilities": [
        "Reentrancy in withdraw()",
        "Owner can drain funds",
        "Missing input validation"
    ],
    "reporter": "test_script"
}

def check_service(url, name):
    """Check if a service is running"""
    try:
        if "midnight-sdk" in url:
            # Use the health endpoint for Node.js
            check_url = NODE_HEALTH_URL
        else:
            # Just a HEAD request to check availability
            check_url = url.split('/')[0] + '//' + url.split('/')[2]
        
        response = requests.get(check_url)
        logger.info(f"{name} service appears to be running")
        return True
    except requests.RequestException as e:
        logger.error(f"{name} service does not appear to be running: {str(e)}")
        return False

def test_direct_node():
    """Test sending data directly to the Node.js service"""
    logger.info("Testing direct submission to Node.js service...")
    try:
        response = requests.post(NODE_URL, json=test_data)
        if response.status_code == 200:
            result = response.json()
            logger.info(f"Direct Node.js test successful: {json.dumps(result)}")
            return True
        else:
            logger.error(f"Direct Node.js test failed: {response.status_code} - {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"Error connecting to Node.js service: {str(e)}")
        return False

def test_flask_endpoint():
    """Test the Flask endpoint"""
    logger.info("Testing Flask endpoint...")
    try:
        response = requests.post(FLASK_URL, json=test_data)
        if response.status_code == 200:
            result = response.json()
            logger.info(f"Flask endpoint test successful: {json.dumps(result)}")
            return True
        else:
            logger.error(f"Flask endpoint test failed: {response.status_code} - {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"Error connecting to Flask service: {str(e)}")
        return False

def run_tests():
    """Run all tests"""
    logger.info("Starting integration tests for PhishNet services")
    
    # Check if services are running
    flask_running = check_service(FLASK_URL, "Flask")
    node_running = check_service(NODE_URL, "Node.js")
    
    if node_running:
        node_result = test_direct_node()
    else:
        logger.warning("Skipping Node.js test since service appears to be down")
        node_result = False
    
    if flask_running and node_running:  # Only test Flask if Node.js is running
        flask_result = test_flask_endpoint()
    else:
        logger.warning("Skipping Flask test since required services appear to be down")
        flask_result = False
    
    # Summary
    logger.info("=== Test Summary ===")
    logger.info(f"Node.js direct test: {'PASS' if node_result else 'FAIL'}")
    logger.info(f"Flask API test: {'PASS' if flask_result else 'FAIL'}")
    
    if flask_result and node_result:
        logger.info("✅ All tests passed! The integration is working correctly.")
    else:
        logger.error("❌ Some tests failed. Please check the logs for details.")

if __name__ == "__main__":
    run_tests()