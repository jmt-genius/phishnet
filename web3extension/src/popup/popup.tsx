import React, { useState } from "react";
import './popup.css';

const Popup = () => {
    const [contractAddress, setContractAddress] = useState(""); // State to store the contract address
    const [analysisResult, setAnalysisResult] = useState<string | null>(null);

    // Handle the contract address input change
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setContractAddress(e.target.value);
    };

    // Handle the "Analyze" button click
    const handleAnalyzeClick = async () => {
        if (!contractAddress) {
            alert("Please enter a valid contract address");
            return;
        }

        // Prepare the payload
        const payload = {
            address: contractAddress,
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

    return (
        <div className="popup-container">
            <h1 className="text-4xl text-green-500">Hello Web3 world ra, bunda</h1>

            {/* Contract address input box */}
            <div className="input-container">
                <input
                    type="text"
                    className="contract-address-input"
                    placeholder="Enter contract address"
                    value={contractAddress}
                    onChange={handleInputChange}
                />
            </div>

            {/* Analyze button */}
            <button
                className="analyze-button"
                onClick={handleAnalyzeClick}
            >
                Analyze
            </button>

            {/* Display analysis result */}
            {analysisResult && (
                <div className="analysis-result">
                    <h2>Analysis Result:</h2>
                    <pre>{analysisResult}</pre>
                </div>
            )}
        </div>
    );
};

export default Popup;
