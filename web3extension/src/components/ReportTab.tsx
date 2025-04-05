import React, { useState } from 'react';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Checkbox } from "./ui/checkbox";
import { Label } from "./ui/label";
import { AlertTriangle, Loader2 } from "lucide-react";
import PageHeader from "./PageHeader";

const ReportTab: React.FC = () => {
  const [url, setUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [issues, setIssues] = useState({
    reentrancy: false,
    ownerDrain: false,
    inputValidation: false
  });
  
  const handleSubmit = () => {
    if (!url) return;
    
    setIsSubmitting(true);
    // Simulate submission process
    setTimeout(() => {
      setIsSubmitting(false);
      setUrl('');
      setIssues({
        reentrancy: false,
        ownerDrain: false,
        inputValidation: false
      });
    }, 1500);
  };
  
  const handleIssueChange = (issue: keyof typeof issues) => {
    setIssues(prev => ({
      ...prev,
      [issue]: !prev[issue]
    }));
  };
  
  return (
    <div className="flex flex-col flex-grow">
      <PageHeader />
      
      <div className="flex-grow p-6 space-y-6 page-content">
        <div className="space-y-2">
          <h2 className="text-lg font-medium text-white">Anonymous Report</h2>
          <p className="text-sm text-gray-400">
            Report suspicious contracts and potential phishing attempts to help protect the community.
          </p>
        </div>
        
        <div className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor="url-input" className="text-sm text-gray-300">Enter URL</Label>
            <Input
              id="url-input"
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="border-phishnet border-opacity-40 bg-secondary"
            />
          </div>
          
          <div className="space-y-4 py-1">
            <div className="flex items-start space-x-3">
              <Checkbox 
                id="reentrancy" 
                checked={issues.reentrancy}
                onCheckedChange={() => handleIssueChange('reentrancy')}
                className="data-[state=checked]:bg-phishnet data-[state=checked]:border-phishnet mt-1"
              />
              <div className="space-y-1">
                <Label htmlFor="reentrancy" className="text-white cursor-pointer">
                  Reentrancy in withdraw
                </Label>
                <p className="text-xs text-gray-400">Contract allows recursive calls during fund withdrawal</p>
              </div>
            </div>
            
            <div className="flex items-start space-x-3">
              <Checkbox 
                id="owner-drain" 
                checked={issues.ownerDrain}
                onCheckedChange={() => handleIssueChange('ownerDrain')}
                className="data-[state=checked]:bg-phishnet data-[state=checked]:border-phishnet mt-1"
              />
              <div className="space-y-1">
                <Label htmlFor="owner-drain" className="text-white cursor-pointer">
                  Owner can drain funds
                </Label>
                <p className="text-xs text-gray-400">Contract owner has unrestricted access to user funds</p>
              </div>
            </div>
            
            <div className="flex items-start space-x-3">
              <Checkbox 
                id="input-validation" 
                checked={issues.inputValidation}
                onCheckedChange={() => handleIssueChange('inputValidation')}
                className="data-[state=checked]:bg-phishnet data-[state=checked]:border-phishnet mt-1"
              />
              <div className="space-y-1">
                <Label htmlFor="input-validation" className="text-white cursor-pointer">
                  Missing input validation
                </Label>
                <p className="text-xs text-gray-400">Contract fails to properly validate user inputs</p>
              </div>
            </div>
          </div>
          
          <Button 
            onClick={handleSubmit}
            disabled={isSubmitting || !url || (!issues.reentrancy && !issues.ownerDrain && !issues.inputValidation)}
            className="w-full bg-phishnet hover:bg-phishnet-dark transition-colors mt-2"
          >
            {isSubmitting ? (
              <>
                <Loader2 size={18} className="mr-2 animate-spin" />
                Submitting...
              </>
            ) : (
              "Submit Report"
            )}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default ReportTab;
