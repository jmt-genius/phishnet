
import React from 'react';

interface PageHeaderProps {
  title?: string;
}

const PageHeader: React.FC<PageHeaderProps> = ({ title = "PhishNet" }) => {
  return (
    <header className="py-5 border-b border-white border-opacity-10">
      <h1 className="text-2xl font-bold text-center text-phishnet">{title}</h1>
    </header>
  );
};

export default PageHeader;
