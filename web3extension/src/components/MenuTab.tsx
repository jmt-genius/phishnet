import React, { useState } from 'react';
import { Switch } from "./ui/switch";
import { Label } from "./ui/label";
import { Shield, ShieldAlert, FileCode } from "lucide-react";
import PageHeader from "./PageHeader";

const MenuTab: React.FC = () => {
  const [autoAnalysis, setAutoAnalysis] = useState(true);
  const [phishingDetection, setPhishingDetection] = useState(true);
  
  return (
    <div className="flex flex-col flex-grow">
      <PageHeader />
      
      <div className="flex-grow p-6 space-y-8 page-content">
        <div className="space-y-2">
          <h2 className="text-lg font-medium text-white mb-5">Security Settings</h2>
          
          <div className="flex items-center justify-between bg-secondary p-4 rounded-lg transition-all hover:bg-opacity-80">
            <div className="flex items-center space-x-3">
              <div className="bg-phishnet bg-opacity-20 p-2 rounded-full">
                <FileCode size={20} className="text-phishnet" />
              </div>
              <Label htmlFor="auto-analysis" className="text-white cursor-pointer">
                Automatic Smart Contract Analysis
              </Label>
            </div>
            <Switch
              id="auto-analysis"
              checked={autoAnalysis}
              onCheckedChange={setAutoAnalysis}
              className="data-[state=checked]:bg-phishnet"
            />
          </div>
          
          <div className="flex items-center justify-between bg-secondary p-4 rounded-lg transition-all hover:bg-opacity-80">
            <div className="flex items-center space-x-3">
              <div className="bg-phishnet bg-opacity-20 p-2 rounded-full">
                <ShieldAlert size={20} className="text-phishnet" />
              </div>
              <Label htmlFor="phishing-detection" className="text-white cursor-pointer">
                Web3 Phishing Links Detection
              </Label>
            </div>
            <Switch
              id="phishing-detection"
              checked={phishingDetection}
              onCheckedChange={setPhishingDetection}
              className="data-[state=checked]:bg-phishnet"
            />
          </div>
        </div>
        
        <div className="text-center">
          <div className="w-24 h-24 mx-auto mb-4 flex items-center justify-center bg-phishnet-dark bg-opacity-20 rounded-full">
            <Shield size={44} className="text-phishnet" />
          </div>
          <p className="text-sm text-gray-400">
            PhishNet is actively protecting your Web3 experience. 
            Stay safe from scams and malicious contracts.
          </p>
        </div>
      </div>
    </div>
  );
};

export default MenuTab;
