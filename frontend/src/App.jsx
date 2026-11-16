import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Sidebar } from './components/Sidebar';
import { AuthPage } from './pages/AuthPage';
import { OverviewPage } from './pages/OverviewPage';
import { NewScanPage } from './pages/NewScanPage';
import { ScanDetailsPage } from './pages/ScanDetailsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { CloudSecurityPage } from './pages/CloudSecurityPage';

function MainApp() {
  const { user, loading } = useAuth();
  const [currentTab, setCurrentTab] = useState('overview');
  const [selectedScanId, setSelectedScanId] = useState(null);

  if (loading) {
    return (
      <div className="app-loader">
        <div className="spinner" />
        <p>Loading CloudGuard...</p>
      </div>
    );
  }

  if (!user) {
    return <AuthPage />;
  }

  const handleSelectScan = (scanId) => {
    setSelectedScanId(scanId);
    setCurrentTab('details');
  };

  const handleScanComplete = (scanId) => {
    setSelectedScanId(scanId);
    setCurrentTab('details');
  };

  return (
    <div className="app-layout">
      <Sidebar
        currentTab={currentTab}
        setTab={(tab) => {
          setCurrentTab(tab);
          if (tab !== 'details') setSelectedScanId(null);
        }}
      />

      <main className="main-content">
        {currentTab === 'overview' && (
          <OverviewPage
            onNavigateToNewScan={() => setCurrentTab('new-scan')}
            onNavigateToCloudSecurity={() => setCurrentTab('cloud-security')}
            onSelectScan={handleSelectScan}
          />
        )}

        {currentTab === 'new-scan' && (
          <NewScanPage onScanComplete={handleScanComplete} />
        )}

        {currentTab === 'history' && (
          <ScanHistoryPage
            onNavigateToNewScan={() => setCurrentTab('new-scan')}
            onSelectScan={handleSelectScan}
          />
        )}

        {currentTab === 'cloud-security' && (
          <CloudSecurityPage />
        )}

        {currentTab === 'details' && selectedScanId && (
          <ScanDetailsPage
            scanId={selectedScanId}
            onBack={() => setCurrentTab('overview')}
          />
        )}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
