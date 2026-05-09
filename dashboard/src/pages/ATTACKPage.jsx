import React, { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import { api } from '../api';

// All 14 MITRE ATT&CK Enterprise tactics in kill-chain order
const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

const TACTIC_ABBR = {
  'Reconnaissance': 'RECON', 'Resource Development': 'RDEV', 'Initial Access': 'INIT',
  'Execution': 'EXEC', 'Persistence': 'PERS', 'Privilege Escalation': 'PRIV',
  'Defense Evasion': 'DEF-EV', 'Credential Access': 'CRED', 'Discovery': 'DISC',
  'Lateral Movement': 'LAT-MOV', 'Collection': 'COLL', 'Command and Control': 'C2',
  'Exfiltration': 'EXFIL', 'Impact': 'IMPACT',
};

function heatColor(count, max) {
  if (!count) return 'var(--bg-void)';
  const ratio = count / max;
  if (ratio > 0.7) return 'rgba(232, 25, 44, 0.85)';
  if (ratio > 0.4) return 'rgba(255, 123, 0, 0.75)';
  if (ratio > 0.1) return 'rgba(245, 196, 0, 0.65)';
  return 'rgba(0, 200, 255, 0.5)';
}

export default function ATTACKPage() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    api.getTTPHeatmap().then(setData).finally(() => setLoading(false));
  }, []);

  // Group by tactic
  const byTactic = {};
  data.forEach(d => {
    if (!byTactic[d.tactic]) byTactic[d.tactic] = [];
    byTactic[d.tactic].push(d);
  });

  const maxCount = Math.max(...data.map(d => d.count), 1);
  const total = data.reduce((s, d) => s + d.count, 0);

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 4 }}>
          THREAT INTELLIGENCE
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>MITRE ATT&CK Coverage</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 6 }}>
          Enterprise Matrix — alerts mapped to tactics and techniques.
        </p>
      </div>

      {/* Stats strip */}
      <div style={{ display: 'flex', gap: 14, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: 'Mapped Techniques', value: data.length },
          { label: 'Total Events', value: total },
          { label: 'Tactics Hit', value: Object.keys(byTactic).length },
          { label: 'Coverage', value: `${Math.round((Object.keys(byTactic).length / 14) * 100)}%` },
        ].map(({ label, value }) => (
          <div key={label} className="card" style={{ padding: '14px 18px', flex: 1, minWidth: 120 }}>
            <div style={{ fontSize: 10, letterSpacing: 1.5, color: 'var(--text-secondary)',
                          fontWeight: 600, textTransform: 'uppercase', marginBottom: 5 }}>
              {label}
            </div>
            <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)',
                          color: 'var(--accent-red)' }}>
              {value}
            </div>
          </div>
        ))}
      </div>

      {/* Tactic columns heatmap */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">ATT&CK Heatmap</span>
          <div style={{ display: 'flex', gap: 8, fontSize: 10 }}>
            {[
              { c: 'rgba(0,200,255,0.5)', l: 'Low' },
              { c: 'rgba(245,196,0,0.65)', l: 'Medium' },
              { c: 'rgba(255,123,0,0.75)', l: 'High' },
              { c: 'rgba(232,25,44,0.85)', l: 'Critical' },
            ].map(({ c, l }) => (
              <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 10, height: 10, background: c, borderRadius: 2 }} />
                <span style={{ color: 'var(--text-muted)' }}>{l}</span>
              </div>
            ))}
          </div>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading ATT&CK data...
          </div>
        ) : (
          <div style={{ padding: 16, overflowX: 'auto' }}>
            <div style={{ display: 'flex', gap: 8, minWidth: 900 }}>
              {TACTICS.map(tactic => {
                const techniques = byTactic[tactic] || [];
                const abbr = TACTIC_ABBR[tactic];
                return (
                  <div key={tactic} style={{ flex: 1, minWidth: 60 }}>
                    {/* Tactic header */}
                    <div style={{
                      background: techniques.length > 0 ? 'var(--accent-red-glow)' : 'var(--bg-void)',
                      border: `1px solid ${techniques.length > 0 ? 'var(--accent-red)44' : 'var(--border)'}`,
                      borderRadius: 4, padding: '6px 4px',
                      textAlign: 'center', marginBottom: 6,
                    }}>
                      <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: 0.5,
                                    color: techniques.length > 0 ? 'var(--accent-red)' : 'var(--text-muted)',
                                    fontFamily: 'var(--font-mono)' }}>
                        {abbr}
                      </div>
                      {techniques.length > 0 && (
                        <div style={{ fontSize: 14, fontWeight: 700, fontFamily: 'var(--font-mono)',
                                      color: 'var(--text-primary)', marginTop: 2 }}>
                          {techniques.reduce((s, t) => s + t.count, 0)}
                        </div>
                      )}
                    </div>

                    {/* Technique cells */}
                    {techniques.map(t => (
                      <div
                        key={t.technique_id}
                        onClick={() => setSelected(t)}
                        style={{
                          background: heatColor(t.count, maxCount),
                          border: '1px solid rgba(255,255,255,0.05)',
                          borderRadius: 3, padding: '5px 4px',
                          marginBottom: 3, cursor: 'pointer',
                          transition: 'transform 0.1s',
                        }}
                        onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.04)'}
                        onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
                        title={`${t.technique_id}: ${t.technique_name} (${t.count} events)`}
                      >
                        <div style={{ fontSize: 9, fontFamily: 'var(--font-mono)',
                                      color: 'rgba(255,255,255,0.9)', fontWeight: 600 }}>
                          {t.technique_id}
                        </div>
                        <div style={{ fontSize: 8, color: 'rgba(255,255,255,0.6)',
                                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {t.technique_name}
                        </div>
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>

            {/* Tactic labels below */}
            <div style={{ display: 'flex', gap: 8, minWidth: 900, marginTop: 8 }}>
              {TACTICS.map(tactic => (
                <div key={tactic} style={{ flex: 1, fontSize: 8, color: 'var(--text-muted)',
                                            textAlign: 'center', lineHeight: 1.2 }}>
                  {tactic}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Technique detail table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Detected Techniques</span>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Technique ID</th>
              <th>Name</th>
              <th>Tactic</th>
              <th>Event Count</th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ textAlign: 'center', padding: 30, color: 'var(--text-muted)' }}>
                  <Shield size={24} style={{ margin: '0 auto 10px', display: 'block', opacity: 0.3 }} />
                  No ATT&CK data yet. Seed the DB or wait for real alerts.
                </td>
              </tr>
            ) : [...data].sort((a, b) => b.count - a.count).map(t => (
              <tr key={t.technique_id}>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12,
                                  color: 'var(--low)', background: 'var(--low-bg)',
                                  padding: '2px 8px', borderRadius: 3 }}>
                    {t.technique_id}
                  </span>
                </td>
                <td>{t.technique_name}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{t.tactic}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{
                      height: 6, borderRadius: 3,
                      width: `${Math.min((t.count / maxCount) * 120, 120)}px`,
                      background: heatColor(t.count, maxCount),
                    }} />
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-red)' }}>
                      {t.count}
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
