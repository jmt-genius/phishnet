import React, { useState } from 'react';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Search, Loader2, AlertCircle, CheckCircle, Info } from "lucide-react";
import PageHeader from "./PageHeader";

const ContractAnalysisTab: React.FC = () => {
  const [contractAddress, setContractAddress] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<any | null>(null);
  
  const handleAnalyze = async () => {
    if (!contractAddress) return;
    
    setIsAnalyzing(true);
    setAnalysisResult(null); // Clear previous results

    // Prepare the payload
    const payload = {
      address: contractAddress,
    };

    try {
      // Send the POST request to analyze the contract
      const response = await fetch('http://127.0.0.1:5001/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (response.ok) {
        setAnalysisResult(data);
      } else {
        setAnalysisResult({ error: 'Error analyzing contract.' });
      }
    } catch (error) {
      setAnalysisResult({ error: 'Error occurred during analysis.' });
    } finally {
      setIsAnalyzing(false); // Stop the loading spinner
    }
  };
  
  return (
    <div className="flex flex-col flex-grow">
      <PageHeader />
      
      <div className="flex-grow p-6 space-y-6 page-content">
        <div className="space-y-2">
          <h2 className="text-lg font-medium text-white">Smart Contract Analysis</h2>
          <p className="text-sm text-gray-400">
            Enter a smart contract address to scan for potential vulnerabilities and risks.
          </p>
        </div>
        
        <div className="space-y-4">
          <div className="relative">
            <Input
              type="text"
              placeholder="Enter smart contract address"
              value={contractAddress}
              onChange={(e) => setContractAddress(e.target.value)}
              className="pl-10 border-phishnet border-opacity-40 bg-secondary"
            />
            <Search 
              size={18} 
              className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" 
            />
          </div>
          
          <Button 
            onClick={handleAnalyze}
            disabled={isAnalyzing || !contractAddress}
            className="w-full bg-phishnet hover:bg-phishnet-dark transition-colors"
          >
            {isAnalyzing ? (
              <>
                <Loader2 size={18} className="mr-2 animate-spin" />
                Analyzing...
              </>
            ) : (
              "Analyze Contract"
            )}
          </Button>
        </div>

        {/* Display formatted result */}
        {analysisResult && (
          <div className="bg-secondary bg-opacity-50 rounded-lg p-5 mt-6 space-y-6">
            {analysisResult.error ? (
              <div className="text-center text-red-500">
                <p>{analysisResult.error}</p>
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <h3 className="text-xl font-semibold text-white">Analysis Result</h3>
                  <div className="flex items-center space-x-2">
                    <div className="flex items-center">
                      {analysisResult.report_summary.overall_assessment === 'High' ? (
                        <AlertCircle size={20} className="text-red-500" />
                      ) : analysisResult.report_summary.overall_assessment === 'Medium' ? (
                        <Info size={20} className="text-yellow-500" />
                      ) : (
                        <CheckCircle size={20} className="text-green-500" />
                      )}
                      <span className="ml-2 text-white">Risk Level: {analysisResult.report_summary.overall_assessment}</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <span className="font-semibold text-white">Vulnerabilities Found:</span> {analysisResult.report_summary.num_vulnerabilities}
                  </div>
                  <div>
                    <span className="font-semibold text-white">Safe to Interact:</span> {analysisResult.report_summary.safe_address === 'Not Safe' ? (
                      <span className="text-red-500">Not Safe</span>
                    ) : (
                      <span className="text-green-500">Safe</span>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ContractAnalysisTab;
