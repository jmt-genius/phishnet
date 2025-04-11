
import React from 'react';
import { cn } from "../../lib/utils";
import { Menu, FileCode, AlertCircle } from "lucide-react";

interface TabNavigationProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

const TabNavigation: React.FC<TabNavigationProps> = ({ activeTab, setActiveTab }) => {
  return (
    <nav className="bg-phishnet bg-opacity-10 rounded-t-xl fixed bottom-0 left-0 right-0 w-[400px] mx-auto shadow-lg">
      <div className="grid grid-cols-3 w-full">
        <button
          onClick={() => setActiveTab('menu')}
          className={cn(
            "flex flex-col items-center justify-center py-3 transition-all duration-300 ease-in-out",
            activeTab === 'menu' ? "phishnet-nav-active" : "text-gray-400 hover:text-gray-200"
          )}
        >
          <Menu size={20} className="mb-1" />
          <span className="text-xs">Menu</span>
        </button>
        
        <button
          onClick={() => setActiveTab('contract')}
          className={cn(
            "flex flex-col items-center justify-center py-3 transition-all duration-300 ease-in-out",
            activeTab === 'contract' ? "phishnet-nav-active" : "text-gray-400 hover:text-gray-200"
          )}
        >
          <FileCode size={20} className="mb-1" />
          <span className="text-xs">Smart Contract</span>
        </button>
        
        <button
          onClick={() => setActiveTab('report')}
          className={cn(
            "flex flex-col items-center justify-center py-3 transition-all duration-300 ease-in-out",
            activeTab === 'report' ? "phishnet-nav-active" : "text-gray-400 hover:text-gray-200"
          )}
        >
          <AlertCircle size={20} className="mb-1" />
          <span className="text-xs">Wallet Analysis</span>
        </button>
      </div>
    </nav>
  );
};

export default TabNavigation;
