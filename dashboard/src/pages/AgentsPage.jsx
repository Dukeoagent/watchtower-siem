import React, { useState, useEffect } from 'react';
import { Monitor, Wifi, WifiOff, Clock } from 'lucide-react';
import { api } from '../api';

export default function AgentsPage() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAgents().then(setAgents).finally(() => setLoading(false));
  }, []);

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 4 }}>
          ENDPOINT MANAGEMENT
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>Monitored Endpoints</h1>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'flex', gap: 14, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: 'Total Agents', value: agents.length,
            icon: Monitor, color: 'var(--accent-red)' },
          { label: 'Active',
            value: agents.filter(a => a.status === 'active').length,
            icon: Wifi, color: 'var(--success)' },
          { label: 'Disconnected',
            value: agents.filter(a => a.status !== 'active').length,
            icon: WifiOff, color: 'var(--high)' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="card" style={{ padding: '16px 20px', flex: 1, minWidth: 140 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: 10, letterSpacing: 1.5, color: 'var(--text-secondary)',
                              fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>
                  {label}
                </div>
                <div style={{ fontSize: 28, fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>
                  {value}
                </div>
              </div>
              <div style={{ width: 34, height: 34, borderRadius: 6,
                            background: `${color}18`, display: 'flex',
                            alignItems: 'center', justifyContent: 'center' }}>
                <Icon size={17} color={color} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Agent table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Endpoint Inventory</span>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Hostname</th>
              <th>IP Address</th>
              <th>OS</th>
              <th>Alerts</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40,
                                            color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : agents.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                  <Monitor size={24} style={{ margin: '0 auto 10px', display: 'block', opacity: 0.3 }} />
                  No agents yet. Install the sensor using the commands in README.md.
                </td>
              </tr>
            ) : agents.map(agent => (
              <tr key={agent.id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: agent.status === 'active' ? 'var(--success)' : 'var(--text-muted)',
                      boxShadow: agent.status === 'active' ? '0 0 6px var(--success)' : 'none',
                    }} />
                    <span style={{ fontSize: 11, color: agent.status === 'active'
                                    ? 'var(--success)' : 'var(--text-muted)' }}>
                      {agent.status === 'active' ? 'Active' : 'Offline'}
                    </span>
                  </div>
                </td>
                <td style={{ fontWeight: 500 }}>{agent.name}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12,
                              color: 'var(--text-secondary)' }}>
                  {agent.ip}
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>{agent.os || 'Unknown'}</td>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13,
                                  color: agent.alert_count > 0 ? 'var(--high)' : 'var(--text-muted)' }}>
                    {agent.alert_count}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                              color: 'var(--text-secondary)' }}>
                  {agent.last_seen ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Clock size={11} />
                      {new Date(agent.last_seen).toLocaleString()}
                    </div>
                  ) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* How to add a new agent */}
      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-header">
          <span className="card-title">Add a New Endpoint</span>
        </div>
        <div style={{ padding: '18px 20px' }}>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 16 }}>
            Run the appropriate command on any machine you want to monitor.
            The sensor will auto-connect to this WatchTower instance.
          </p>
          {[
            { os: 'Linux / Ubuntu / Debian', cmd: 'bash <(curl -s http://YOUR_SERVER_IP:8000/install/linux)' },
            { os: 'macOS',                   cmd: 'bash <(curl -s http://YOUR_SERVER_IP:8000/install/mac)' },
            { os: 'Windows (PowerShell)',    cmd: 'iwr http://YOUR_SERVER_IP:8000/install/windows | iex' },
          ].map(({ os, cmd }) => (
            <div key={os} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 5 }}>{os}</div>
              <code style={{
                display: 'block', background: 'var(--bg-void)', border: '1px solid var(--border)',
                padding: '10px 14px', borderRadius: 4, fontFamily: 'var(--font-mono)',
                fontSize: 12, color: '#7fbbff', letterSpacing: 0.3,
              }}>
                {cmd}
              </code>
            </div>
          ))}
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 12 }}>
            Replace <code style={{ fontFamily: 'var(--font-mono)' }}>YOUR_SERVER_IP</code> with your server's
            actual IP address. See README.md for detailed setup instructions.
          </p>
        </div>
      </div>
    </div>
  );
}
