import React, { useState } from 'react';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Search, Loader2 } from "lucide-react";
import PageHeader from "./PageHeader";
import * as Dialog from '@radix-ui/react-dialog';
import { X } from "lucide-react"; // Ensure you're importing X properly

const WalletAnalysisTab: React.FC = () => {
  const [walletAddress, setWalletAddress] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<any | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false); // Dialog state
  
  const handleAnalyze = async () => {
    if (!walletAddress) return;
    
    setIsAnalyzing(true);
    setAnalysisResult(null); // Clear previous results

    // Prepare the payload
    const payload = {
      address: walletAddress,
    };

    try {
      // Send the POST request to analyze the wallet
      const response = await fetch('http://127.0.0.1:5000/analyze_wallet', {
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
        setAnalysisResult({ error: 'Error analyzing wallet.' });
      }
    } catch (error) {
      setAnalysisResult({ error: 'Error occurred during analysis.' });
    } finally {
      setIsAnalyzing(false); // Stop the loading spinner
      setDialogOpen(true); // Open dialog after analysis
    }
  };

  // Function to display only the parameters that are true
  const displayTrueParams = () => {
    if (!analysisResult) return null;

    const trueParams = [];
    const walletAnalysis = analysisResult.wallet_analysis;

    // Check each parameter and add to list if true
    if (walletAnalysis.interacted_with_phishing) trueParams.push('Interacted with phishing address');
    if (walletAnalysis.delegatecall_detected) trueParams.push('Delegatecall detected');
    if (walletAnalysis.gasless_transactions) trueParams.push('Gasless transactions');
    if (walletAnalysis.proxy_behavior) trueParams.push('Proxy behavior detected');
    if (walletAnalysis.balance_draining) trueParams.push('Balance draining detected');
    if (walletAnalysis.multisend_behavior) trueParams.push('Multisend behavior detected');
    if (walletAnalysis.phishing_tag) trueParams.push('Phishing address detected');

    return trueParams.length > 0 ? trueParams : ['No true parameters found'];
  };
  
  return (
    <div className="flex flex-col flex-grow">
      <PageHeader />
      
      <div className="flex-grow p-6 space-y-6 page-content">
        <div className="space-y-2">
          <h2 className="text-lg font-medium text-white">Wallet Analysis</h2>
          <p className="text-sm text-gray-400">
            Enter a wallet address to scan for potential security risks.
          </p>
        </div>
        
        <div className="space-y-4">
          <div className="relative">
            <Input
              type="text"
              placeholder="Enter wallet address"
              value={walletAddress}
              onChange={(e) => setWalletAddress(e.target.value)}
              className="pl-10 border-phishnet border-opacity-40 bg-secondary"
            />
            <Search 
              size={18} 
              className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" 
            />
          </div>
          
          <Button 
            onClick={handleAnalyze}
            disabled={isAnalyzing || !walletAddress}
            className="w-full bg-phishnet hover:bg-phishnet-dark transition-colors"
          >
            {isAnalyzing ? (
              <>
                <Loader2 size={18} className="mr-2 animate-spin" />
                Analyzing...
              </>
            ) : (
              "Analyze Wallet"
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
                    <span className="text-white">Risk Score: {analysisResult.risk_score}%</span>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <span className="font-semibold text-white">Wallet Address:</span> {analysisResult.wallet_analysis.address}
                  </div>
                  <div>
                    <span className="font-semibold text-white">Transactions Found:</span> {analysisResult.wallet_analysis.transaction_count}
                  </div>
                  <div>
                    <span className="font-semibold text-white">Safe to Interact:</span> {analysisResult.wallet_analysis.interacted_with_phishing ? (
                      <span className="text-red-500">Not Safe</span>
                    ) : (
                      <span className="text-green-500">Safe</span>
                    )}
                  </div>

                  {/* List true parameters */}
                  <div>
                    <span className="font-semibold text-white">True Parameters:</span>
                    <ul className="text-white">
                      {displayTrueParams().map((param, index) => (
                        <li key={index}>{param}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* Dialog for Analysis Completion */}
      <Dialog.Root open={dialogOpen} onOpenChange={setDialogOpen}>
        <Dialog.Trigger />
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/80" />
          <Dialog.Content className="fixed left-[50%] top-[50%] z-50 grid w-full max-w-lg translate-x-[-50%] translate-y-[-50%] gap-4 border bg-background p-6 shadow-lg">
            <Dialog.Close className="absolute right-4 top-4 rounded-sm opacity-70 hover:opacity-100">
              <X className="h-4 w-4" />
              <span className="sr-only">Close</span>
            </Dialog.Close>
            <Dialog.Title className="text-xl font-semibold">Analysis Completed</Dialog.Title>
            <Dialog.Description>
              <p className="text-sm text-muted-foreground">
                The wallet analysis has been completed successfully. You can now review the results.
              </p>
            </Dialog.Description>
            <div className="flex justify-end space-x-2">
              <Button onClick={() => setDialogOpen(false)} className="w-full bg-phishnet hover:bg-phishnet-dark">
                OK
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
};

export default WalletAnalysisTab;
