import React, { useState } from 'react';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Search, Loader2 } from "lucide-react";
import PageHeader from "./PageHeader";
import * as Dialog from '@radix-ui/react-dialog';
import { X } from "lucide-react"; // Ensure you're importing X properly

const ContractAnalysisTab: React.FC = () => {
  const [contractAddress, setContractAddress] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<any | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false); // Dialog state
  
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
      setDialogOpen(true); // Open dialog after analysis
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
                    {/* Add appropriate icons and info */}
                    <span className="text-white">{analysisResult.report_summary.overall_assessment}</span>
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
                The analysis has been completed successfully. You can now review the results.
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

export default ContractAnalysisTab;
