const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());

const PROOF_SERVER_URL = "http://localhost:6300"; // Proof server URL

// Middleware for logging incoming requests
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

app.post('/midnight-sdk', async (req, res) => {
    console.log("Received request to submit scam report to Midnight SDK");
    
    try {
        const { contractAddress, riskLevel, vulnerabilities, reporter } = req.body;
        
        // Validate required fields
        if (!contractAddress || !riskLevel || !vulnerabilities || !reporter) {
            console.error("Missing required fields in request");
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Wrap data for ZK submission
        const scamReport = {
            contractAddress,
            riskLevel,
            vulnerabilities: Array.isArray(vulnerabilities) ? vulnerabilities : [vulnerabilities],
            reporter,
            timestamp: new Date().toISOString(),
            source: "Gemini-via-PhishNet"
        };

        console.log(`Submitting report to Midnight Proof Server: ${JSON.stringify(scamReport)}`);
        
        // Mock the submission for testing purposes
        // In a real implementation, you would connect to the actual API
        // const response = await axios.post(`${PROOF_SERVER_URL}/submit`, scamReport);
        
        // Instead, simulate a successful response
        const mockHash = "0x" + Array(64).fill().map(() => Math.floor(Math.random() * 16).toString(16)).join('');
        
        console.log(`Report submitted successfully. Hash/CID: ${mockHash}`);

        res.json({ 
            status: "submitted", 
            hash: mockHash,
            timestamp: scamReport.timestamp 
        });
    } catch (error) {
        if (error.response) {
            // The Midnight server responded with an error
            console.error("Midnight server error:", error.response.data);
            res.status(error.response.status).json({ 
                error: "Proof server error", 
                details: error.response.data 
            });
        } else if (error.request) {
            // No response received from the Midnight server
            console.error("No response from Midnight server:", error.request);
            res.status(503).json({ 
                error: "Unable to reach the proof server. Please try again later." 
            });
        } else {
            // Something else went wrong
            console.error("Error processing request:", error.message);
            res.status(500).json({ error: error.message });
        }
    }
});

// For testing purposes - add a health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: "healthy" });
});

app.listen(3000, () => console.log('Node.js service running on port 3000'));

// Handle server shutdown gracefully
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    process.exit(0);
});