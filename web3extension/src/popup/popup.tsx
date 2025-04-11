
import React, { useState } from 'react';
import TabNavigation from '../components/TabNavigation';
import MenuTab from '../components/MenuTab';
import ContractAnalysisTab from '../components/ContractAnalysisTab';
import ReportTab from '../components/ReportTab';

const Index = () => {
  const [activeTab, setActiveTab] = useState('menu');

  return (
    <div className="min-h-screen flex flex-col overflow-y-auto phishnet-gradient">
      <div className="flex-grow overflow-y-auto pb-16">
        {activeTab === 'menu' && <MenuTab />}
        {activeTab === 'contract' && <ContractAnalysisTab />}
        {activeTab === 'report' && <ReportTab />}
      </div>
      
      <TabNavigation activeTab={activeTab} setActiveTab={setActiveTab} />
    </div>
  );
};
export default Index;
