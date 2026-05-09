import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Overview from './pages/Overview';
import AlertsPage from './pages/AlertsPage';
import AgentsPage from './pages/AgentsPage';
import ATTACKPage from './pages/ATTACKPage';
import FIMPage from './pages/FIMPage';
import SettingsPage from './pages/SettingsPage';
import { openAlertSocket } from './api';

export default function App() {
  const [liveAlerts, setLiveAlerts] = useState([]);

  useEffect(() => {
    // Open WebSocket for real-time alert notifications
    const ws = openAlertSocket((alert) => {
      setLiveAlerts(prev => [alert, ...prev].slice(0, 5)); // keep last 5 live alerts
    });
    return () => ws.close?.();
  }, []);

  return (
    <BrowserRouter>
      <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
        <Sidebar />

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <Topbar liveAlerts={liveAlerts} />

          <main style={{
            flex: 1,
            overflowY: 'auto',
            background: 'var(--bg-base)',
            padding: '24px',
          }}>
            <Routes>
              <Route path="/"         element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<Overview />} />
              <Route path="/alerts"   element={<AlertsPage />} />
              <Route path="/agents"   element={<AgentsPage />} />
              <Route path="/attack"   element={<ATTACKPage />} />
              <Route path="/fim"      element={<FIMPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}
