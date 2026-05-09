import React, { useState, useEffect } from 'react';
import { FolderSearch, FilePlus, FileMinus, FileEdit } from 'lucide-react';
import { api } from '../api';

const EVENT_ICONS = {
  added:    { icon: FilePlus,  color: 'var(--success)' },
  modified: { icon: FileEdit,  color: 'var(--high)' },
  deleted:  { icon: FileMinus, color: 'var(--critical)' },
};

export default function FIMPage() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getFIMEvents().then(setEvents).finally(() => setLoading(false));
  }, []);

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 4 }}>
          ENDPOINT DETECTION
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>File Integrity Monitoring</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 6 }}>
          Real-time tracking of changes to monitored files and directories.
          Unexpected changes to system files are a key indicator of compromise.
        </p>
      </div>

      {/* Summary */}
      <div style={{ display: 'flex', gap: 14, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: 'Modified', count: events.filter(e => e.extra?.syscheck?.event === 'modified').length,
            color: 'var(--high)' },
          { label: 'Added',    count: events.filter(e => e.extra?.syscheck?.event === 'added').length,
            color: 'var(--success)' },
          { label: 'Deleted',  count: events.filter(e => e.extra?.syscheck?.event === 'deleted').length,
            color: 'var(--critical)' },
        ].map(({ label, count, color }) => (
          <div key={label} className="card" style={{ padding: '14px 18px', flex: 1 }}>
            <div style={{ fontSize: 10, letterSpacing: 1.5, color: 'var(--text-secondary)',
                          fontWeight: 600, textTransform: 'uppercase', marginBottom: 5 }}>
              {label}
            </div>
            <div style={{ fontSize: 26, fontWeight: 700, fontFamily: 'var(--font-mono)', color }}>
              {count}
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">File Change Events</span>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Event</th>
              <th>File Path</th>
              <th>Endpoint</th>
              <th>Hash (Before → After)</th>
              <th>Severity</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 40,
                                            color: 'var(--text-muted)' }}>Loading...</td></tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                  <FolderSearch size={24} style={{ margin: '0 auto 10px', display: 'block', opacity: 0.3 }} />
                  No file integrity events yet.
                </td>
              </tr>
            ) : events.map(ev => {
              const sc = ev.extra?.syscheck || {};
              const evType = sc.event || 'modified';
              const { icon: Icon, color } = EVENT_ICONS[evType] || EVENT_ICONS.modified;

              return (
                <tr key={ev.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <Icon size={14} color={color} />
                      <span style={{ fontSize: 11, color, fontWeight: 600, textTransform: 'uppercase',
                                      letterSpacing: 0.5 }}>
                        {evType}
                      </span>
                    </div>
                  </td>
                  <td>
                    <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#7fbbff',
                                    background: 'var(--bg-void)', padding: '2px 6px', borderRadius: 3 }}>
                      {sc.path || ev.description}
                    </code>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>{ev.agent}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                    {sc.md5_before ? (
                      <span>
                        <span style={{ color: 'var(--critical)' }}>{sc.md5_before?.slice(0, 8)}…</span>
                        {' → '}
                        <span style={{ color: 'var(--success)' }}>{sc.md5_after?.slice(0, 8)}…</span>
                      </span>
                    ) : '—'}
                  </td>
                  <td><span className={`badge badge-${ev.severity}`}>{ev.severity}</span></td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                                color: 'var(--text-secondary)' }}>
                    {new Date(ev.timestamp).toLocaleString()}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
