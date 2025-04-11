import React, { useState, useEffect } from 'react';
import { Switch } from "./ui/switch";
import { Label } from "./ui/label";
import { Shield, ShieldAlert, FileCode, AlertTriangle } from "lucide-react";
import PageHeader from "./PageHeader";

const SCAM_CATEGORIES = [
  'Rug Pulls',
  'Ponzi Schemes & HYIPs',
  'Phishing Attacks',
  'Wallet Drainers',
  'NFT Scams',
  'Impersonation Scams',
  'Pump & Dump Schemes',
  'Malicious Smart Contracts',
  'Fake Airdrops / Giveaways',
  'Exchange / Wallet Scams',
  'Social Media / Influencer Scams',
  'Token Approval Exploits'
] as const;

type ScamCategory = typeof SCAM_CATEGORIES[number];

const MenuTab: React.FC = () => {
  const [autoAnalysis, setAutoAnalysis] = useState(true);
  const [phishingDetection, setPhishingDetection] = useState(true);
  const [reportUrl, setReportUrl] = useState('');
  const [reportCause, setReportCause] = useState<ScamCategory>(SCAM_CATEGORIES[0]);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    // Get the current active tab's URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.url) {
        setReportUrl(tabs[0].url);
      }
    });
  }, []);

  const handleReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportUrl.trim() || !reportCause.trim()) return;

    setIsSubmitting(true);
    try {
      // First check if URL already exists
      const checkResponse = await fetch(`http://localhost:3000/api/check-url?url=${encodeURIComponent(reportUrl)}`);
      const checkData = await checkResponse.json();

      if (checkData.exists) {
        alert('This URL has already been reported and is being analyzed. Thank you for your vigilance!');
        return;
      }

      // If URL doesn't exist, submit the report
      const response = await fetch('http://localhost:3000/api/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: reportUrl,
          ipAddress: await getCurrentTabIP(),
          cause: reportCause
        }),
      });

      const data = await response.json();
      
      if (data.success) {
        alert('Thank you for reporting. Our team will review this website.');
        setReportUrl('');
        setReportCause(SCAM_CATEGORIES[0]);
      } else {
        alert(data.error || 'Failed to report URL. Please try again.');
      }
    } catch (error) {
      console.error('Error reporting URL:', error);
      alert('Failed to report URL. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const getCurrentTabIP = async (): Promise<string> => {
    return new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        if (tabs[0]?.url) {
          try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            resolve(data.ip);
          } catch (error) {
            resolve('unknown');
          }
        } else {
          resolve('unknown');
        }
      });
    });
  };

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
        
        <div className="space-y-2">
          <h2 className="text-lg font-medium text-white mb-5">Report Suspicious Website</h2>
          <form onSubmit={handleReport} className="flex flex-col space-y-4 bg-secondary p-4 rounded-lg">
            <div className="flex-grow space-y-3">
              <input
                type="url"
                value={reportUrl}
                onChange={(e) => setReportUrl(e.target.value)}
                placeholder="Enter suspicious website URL"
                className="w-full px-3 py-2 bg-background rounded border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:border-phishnet"
                required
              />
              <select
                value={reportCause}
                onChange={(e) => setReportCause(e.target.value as ScamCategory)}
                className="w-full px-3 py-2 bg-background rounded border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:border-phishnet"
                required
              >
                {SCAM_CATEGORIES.map((category) => (
                  <option key={category} value={category}>
                    {category}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-phishnet text-white rounded hover:bg-opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? 'Reporting...' : 'Report'}
            </button>
          </form>
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
