import React, { useState } from 'react';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Search, Loader2 } from "lucide-react";
import PageHeader from "./PageHeader";

const ContractAnalysisTab: React.FC = () => {
  const [contractAddress, setContractAddress] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  
  const handleAnalyze = () => {
    if (!contractAddress) return;
    
    setIsAnalyzing(true);
    // Simulate analysis process
    setTimeout(() => {
      setIsAnalyzing(false);
    }, 2000);
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
        
        <div className="bg-secondary bg-opacity-50 rounded-lg p-5 mt-6">
          <div className="flex items-center justify-center h-32">
            <p className="text-gray-400 text-sm">
              Results will appear here after analysis
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ContractAnalysisTab;
