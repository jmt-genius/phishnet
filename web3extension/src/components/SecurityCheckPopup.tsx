import React from 'react';
import { Shield, AlertTriangle, X } from 'lucide-react';

interface SecurityCheckPopupProps {
  url: string;
  onCancel: () => void;
  onContinue: () => void;
  isSafe?: boolean;
}

const SecurityCheckPopup: React.FC<SecurityCheckPopupProps> = ({
  url,
  onCancel,
  onContinue,
  isSafe = true
}) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-secondary rounded-lg shadow-xl w-[400px] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between bg-background p-4 border-b border-gray-600">
          <div className="flex items-center space-x-2">
            <img src="/icon48.png" alt="ScamSniffer" className="w-6 h-6" />
            <span className="text-white font-medium">ScamSniffer</span>
          </div>
          <span className="px-3 py-1 bg-phishnet bg-opacity-20 text-phishnet text-sm rounded-full">
            Premium Plan
          </span>
        </div>

        {/* Alert Banner */}
        <div className="bg-background/50 p-3 flex items-center space-x-2 text-sm">
          <AlertTriangle size={16} className="text-phishnet" />
          <span className="text-gray-300">Q1 2025 Phishing Trends and Insights.</span>
          <a href="#" className="text-phishnet hover:underline">Learn more</a>
        </div>

        {/* Content */}
        <div className="p-6 flex flex-col items-center space-y-4">
          {isSafe ? (
            <div className="w-12 h-12 rounded-full bg-green-500 flex items-center justify-center">
              <Shield size={24} className="text-white" />
            </div>
          ) : (
            <div className="w-12 h-12 rounded-full bg-red-500 flex items-center justify-center">
              <AlertTriangle size={24} className="text-white" />
            </div>
          )}
          
          <div className="text-center">
            <h2 className="text-white text-lg font-medium mb-1">Security Check</h2>
            <p className="text-gray-400 text-sm break-all">{url}</p>
          </div>
        </div>

        {/* Actions */}
        <div className="p-4 flex space-x-3 border-t border-gray-600">
          <button
            onClick={onCancel}
            className="flex-1 px-4 py-2 rounded bg-background hover:bg-opacity-80 transition-all text-white flex items-center justify-center space-x-2"
          >
            <X size={18} />
            <span>CANCEL</span>
          </button>
          <button
            onClick={onContinue}
            className="flex-1 px-4 py-2 rounded bg-phishnet hover:bg-opacity-90 transition-all text-white flex items-center justify-center space-x-2"
          >
            <span>CONTINUE</span>
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none">
              <path d="M5 12H19M19 12L12 5M19 12L12 19" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
};

export default SecurityCheckPopup;
