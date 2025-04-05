import React, { useState } from "react";
import './popup.css';

const Popup = () => {
    const [contractAddress, setContractAddress] = useState(""); // State to store the contract address
    const [analysisResult, setAnalysisResult] = useState<string | null>(null);
    const [autoAnalyze, setAutoAnalyze] = useState(false); // Automatic Smart Contract Analysis
    const [phishingLinks, setPhishingLinks] = useState(false); // Web3 Phishing Links switch
    const [url, setUrl] = useState(""); // State for anonymous report URL
    const [reentrancy, setReentrancy] = useState(false);
    const [ownerDrain, setOwnerDrain] = useState(false);
    const [missingInput, setMissingInput] = useState(false);
    const [activeTab, setActiveTab] = useState("menu"); // Tab for active section

    // Handle the contract address input change
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setContractAddress(e.target.value);
    };

    // Handle the URL input change for anonymous report
    const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setUrl(e.target.value);
    };

    // Handle the "Analyze" button click for Smart Contract Analysis
    const handleAnalyzeClick = async () => {
        if (!contractAddress) {
            alert("Please enter a valid contract address");
            return;
        }

        // Prepare the payload
        const payload = {
            address: contractAddress,
            autoAnalyze,
            phishingLinks
        };

        try {
            const response = await fetch('http://127.0.0.1:5000/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });

            const data = await response.json();
            console.log('Analysis Result:', data);

            // Store the result in state
            setAnalysisResult(JSON.stringify(data, null, 2)); // Pretty print the result

            // Send the result to the content script
            chrome.runtime.sendMessage({
                type: "ANALYSIS_RESULT",
                data: data,
            });

            alert('Analysis completed. Check the result below.');
        } catch (error) {
            console.error('Error:', error);
            alert('Error during analysis.');
        }
    };

    // Handle the "Report" button click for Anonymous Report
    const handleReportClick = async () => {
        if (!url) {
            alert("Please enter a valid URL");
            return;
        }

        const reportPayload = {
            url: url,
            reentrancy,
            ownerDrain,
            missingInput
        };

        try {
            // Here we can send the report data to the backend or log it
            console.log("Reporting issue with the following details:", reportPayload);
            alert("Report submitted successfully!");
        } catch (error) {
            console.error('Error in report submission:', error);
            alert('Error during report submission.');
        }
    };

    return (
        <div className="popup-container">
            <h1 className="title">PhishNet</h1>

            {/* Navbar */}
            <div className="navbar">
                <button onClick={() => setActiveTab("menu")}>Menu</button>
                <div className="section-separator"></div>
                <button onClick={() => setActiveTab("smartContractAnalysis")}>Smart Contract Analysis</button>
                <button onClick={() => setActiveTab("report")}>Anonymous Report</button>
            </div>

            {/* Menu Section */}
            {activeTab === "menu" && (
                <div>
                    <div className="switch-container">
                        <label className="switch">
                            <input
                                type="checkbox"
                                checked={autoAnalyze}
                                onChange={() => setAutoAnalyze(!autoAnalyze)}
                            />
                            <span className="slider round"></span>
                        </label>
                        <span>Automatic Smart Contract Analysis</span>
                    </div>

                    <div className="switch-container">
                        <label className="switch">
                            <input
                                type="checkbox"
                                checked={phishingLinks}
                                onChange={() => setPhishingLinks(!phishingLinks)}
                            />
                            <span className="slider round"></span>
                        </label>
                        <span>Web3 Phishing Links Detection</span>
                    </div>
                </div>
            )}
            <div className="section-separator"></div>
            {/* Smart Contract Analysis Section */}
            {activeTab === "smartContractAnalysis" && (
                <div>
                    <div className="input-container">
                        <input
                            type="text"
                            className="contract-address-input"
                            placeholder="Enter smart contract address"
                            value={contractAddress}
                            onChange={handleInputChange}
                        />
                    </div>

                    <button className="analyze-button" onClick={handleAnalyzeClick}>Analyze</button>

                    {analysisResult && (
                        <div className="analysis-result">
                            <h2>Analysis Result:</h2>
                            <pre>{analysisResult}</pre>
                        </div>
                    )}
                </div>
            )}

            {/* Anonymous Report Section */}
            {activeTab === "report" && (
                <div>
                    <div className="input-container">
                        <input
                            type="text"
                            className="contract-address-input"
                            placeholder="Enter URL"
                            value={url}
                            onChange={handleUrlChange}
                        />
                    </div>

                    <div className="checkbox-container">
                        <label>
                            <input
                                type="checkbox"
                                checked={reentrancy}
                                onChange={() => setReentrancy(!reentrancy)}
                            />
                            Reentrancy in withdraw
                        </label>
                        <label>
                            <input
                                type="checkbox"
                                checked={ownerDrain}
                                onChange={() => setOwnerDrain(!ownerDrain)}
                            />
                            Owner can drain funds
                        </label>
                        <label>
                            <input
                                type="checkbox"
                                checked={missingInput}
                                onChange={() => setMissingInput(!missingInput)}
                            />
                            Missing input validation
                        </label>
                    </div>

                    <button className="analyze-button" onClick={handleReportClick}>Report</button>
                </div>
            )}
        </div>
    );
};

export default Popup;
