import React, { useState, useEffect } from 'react';
import { Search, X, ChevronRight, AlertOctagon } from 'lucide-react';
import { api } from '../api';

function SeverityBadge({ sev }) {
  return <span className={`badge badge-${sev}`}>{sev}</span>;
}

function AlertModal({ alert, onClose }) {
  if (!alert) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ padding: '18px 22px', borderBottom: '1px solid var(--border)',
                      display: 'flex', alignItems: 'flex-start', gap: 14 }}>
          <div style={{
            borderLeft: `3px solid var(--${alert.severity})`,
            paddingLeft: 14, flex: 1,
          }}>
            <div style={{ fontSize: 10, letterSpacing: 1.5, color: 'var(--text-muted)',
                          marginBottom: 5 }}>
              ALERT #{alert.id} · RULE {alert.rule_id}
            </div>
            <div style={{ fontSize: 17, fontWeight: 600, color: 'var(--text-primary)',
                          lineHeight: 1.3, marginBottom: 8 }}>
              {alert.rule_description}
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <SeverityBadge sev={alert.severity} />
              {alert.ttp_id && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                                color: 'var(--low)', background: 'var(--low-bg)',
                                padding: '2px 8px', borderRadius: 3 }}>
                  {alert.ttp_id} · {alert.ttp_tactic}
                </span>
              )}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none',
                                              cursor: 'pointer', color: 'var(--text-muted)',
                                              marginTop: -2 }}>
            <X size={18} />
          </button>
        </div>

        {/* Details grid */}
        <div style={{ padding: '16px 22px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
            {[
              { label: 'Endpoint',   value: alert.agent_name },
              { label: 'IP Address', value: alert.agent_ip },
              { label: 'Rule Level', value: `Level ${alert.rule_level} / 15` },
              { label: 'Rule Groups', value: alert.rule_groups },
              { label: 'Timestamp',  value: new Date(alert.timestamp).toLocaleString() },
              { label: 'TTP Name',   value: alert.ttp_name || '—' },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: 'var(--bg-void)', borderRadius: 4, padding: '10px 12px' }}>
                <div style={{ fontSize: 10, letterSpacing: 1.2, color: 'var(--text-muted)',
                              fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>
                  {label}
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)',
                              fontFamily: label === 'IP Address' || label === 'Rule Level'
                                ? 'var(--font-mono)' : 'inherit' }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Raw log */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, letterSpacing: 1.5, color: 'var(--text-muted)',
                          fontWeight: 600, textTransform: 'uppercase', marginBottom: 8 }}>
              Raw Log
            </div>
            <div style={{ background: 'var(--bg-void)', border: '1px solid var(--border)',
                          borderRadius: 4, padding: '12px 14px',
                          fontFamily: 'var(--font-mono)', fontSize: 12,
                          color: '#6b8aad', lineHeight: 1.6,
                          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                          maxHeight: 120, overflow: 'auto' }}>
              {alert.full_log}
            </div>
          </div>

          {/* Remediation */}
          {alert.remediation && (
            <div style={{
              background: '#001a0e',
              border: '1px solid var(--success)33',
              borderLeft: '3px solid var(--success)',
              borderRadius: 5,
              padding: '14px 16px',
            }}>
              <div style={{ fontSize: 10, letterSpacing: 1.5, color: 'var(--success)',
                            fontWeight: 700, textTransform: 'uppercase', marginBottom: 8 }}>
                ✅ Suggested Remediation
              </div>
              <div style={{ fontSize: 13, color: '#a0d4b8', lineHeight: 1.7 }}>
                {alert.remediation}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [search, setSearch] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const params = severityFilter ? `?severity=${severityFilter}&limit=200` : '?limit=200';
        const data = await api.getAlerts(params);
        setAlerts(data);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [severityFilter]);

  const filtered = alerts.filter(a =>
    !search ||
    a.rule_description?.toLowerCase().includes(search.toLowerCase()) ||
    a.agent_name?.toLowerCase().includes(search.toLowerCase()) ||
    String(a.rule_id).includes(search)
  );

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 4 }}>
          ENDPOINT DETECTION
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>Security Alerts</h1>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%',
                                      transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search alerts, endpoints, rule IDs..."
            style={{ paddingLeft: 32 }}
          />
        </div>

        <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
                style={{ width: 160 }}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <div style={{ display: 'flex', alignItems: 'center', fontSize: 12,
                      color: 'var(--text-muted)', padding: '0 8px' }}>
          {filtered.length} alerts
        </div>
      </div>

      {/* Table */}
      <div className="card">
        <div style={{ overflow: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 90 }}>Severity</th>
                <th>Description</th>
                <th>Endpoint</th>
                <th>ATT&CK</th>
                <th style={{ width: 150 }}>Timestamp</th>
                <th style={{ width: 30 }}></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40,
                                              color: 'var(--text-muted)' }}>Loading...</td></tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                    <AlertOctagon size={24} style={{ margin: '0 auto 10px', display: 'block', opacity: 0.4 }} />
                    No results found
                  </td>
                </tr>
              ) : filtered.map(a => (
                <tr key={a.id} onClick={() => setSelected(a)}>
                  <td><span className={`badge badge-${a.severity}`}>{a.severity}</span></td>
                  <td style={{ maxWidth: 300 }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.rule_description}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Rule #{a.rule_id}
                    </div>
                  </td>
                  <td>
                    <div style={{ fontSize: 13 }}>{a.agent_name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {a.agent_ip}
                    </div>
                  </td>
                  <td>
                    {a.ttp_id ? (
                      <div>
                        <span style={{ fontSize: 11,
                                        color: 'var(--low)', background: 'var(--low-bg)',
                                        padding: '2px 6px', borderRadius: 3,
                                        border: '1px solid var(--low)44',
                                        display: 'inline-block' }}>
                          {a.ttp_name || a.ttp_tactic}
                        </span>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)',
                                       fontFamily: 'var(--font-mono)', marginTop: 3 }}>
                          {a.ttp_id}
                        </div>
                      </div>
                    ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                                color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {new Date(a.timestamp).toLocaleString()}
                  </td>
                  <td><ChevronRight size={14} color="var(--text-muted)" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selected && <AlertModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
