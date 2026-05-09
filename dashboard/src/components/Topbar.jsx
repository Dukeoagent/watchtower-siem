import React, { useState } from 'react';
import { Bell, X, Zap, Check, Loader } from 'lucide-react';
import { api } from '../api';

const SEV_META = {
  critical: { label: 'Critical', color: 'var(--critical)', bg: 'var(--critical-bg)' },
  high:     { label: 'High',     color: 'var(--high)',     bg: 'var(--high-bg)' },
  medium:   { label: 'Medium',   color: 'var(--medium)',   bg: 'var(--medium-bg)' },
  low:      { label: 'Low',      color: 'var(--low)',      bg: 'var(--low-bg)' },
};

function DemoButton() {
  const [open, setOpen]       = useState(false);
  const [busy, setBusy]       = useState(null);     // severity in flight
  const [last, setLast]       = useState(null);     // last result for inline feedback

  async function fire(severity) {
    if (busy) return;
    setBusy(severity);
    setLast(null);
    try {
      const result = await api.triggerDemoAlert(severity);
      setLast({ ok: true, severity, ...result });
    } catch (e) {
      setLast({ ok: false, severity, error: String(e) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        title="Trigger a live demo alert"
        style={{
          background: open ? 'var(--accent-red)' : 'transparent',
          border: '1px solid var(--accent-red)',
          color: open ? '#fff' : 'var(--accent-red)',
          cursor: 'pointer',
          height: 32, padding: '0 12px', borderRadius: 6,
          fontSize: 11, fontWeight: 700, letterSpacing: 1.2,
          display: 'flex', alignItems: 'center', gap: 6,
          fontFamily: 'var(--font-mono)',
        }}
      >
        <Zap size={13} /> DEMO
      </button>

      {open && (
        <div style={{
          position: 'absolute', top: 40, right: 0,
          width: 300,
          background: 'var(--bg-panel)',
          border: '1px solid var(--border-glow)',
          borderRadius: 6,
          zIndex: 999,
          overflow: 'hidden',
          boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
        }}>
          <div style={{
            padding: '10px 14px',
            borderBottom: '1px solid var(--border)',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: 1, color: 'var(--text-secondary)' }}>
              TRIGGER LIVE ALERT
            </span>
            <button onClick={() => setOpen(false)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
              <X size={14} />
            </button>
          </div>

          <div style={{ padding: '10px 14px', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
            Each click creates a live alert from your IP / city / ISP. Anyone viewing this dashboard sees it instantly.
          </div>

          <div style={{ padding: '0 12px 12px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {Object.entries(SEV_META).map(([sev, m]) => (
              <button
                key={sev}
                onClick={() => fire(sev)}
                disabled={busy !== null}
                style={{
                  background: m.bg,
                  border: `1px solid ${m.color}66`,
                  color: m.color,
                  padding: '8px 10px',
                  borderRadius: 5,
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: 1,
                  textTransform: 'uppercase',
                  cursor: busy ? 'wait' : 'pointer',
                  opacity: busy && busy !== sev ? 0.4 : 1,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                  fontFamily: 'var(--font-mono)',
                  transition: 'transform 0.1s',
                }}
                onMouseDown={e => e.currentTarget.style.transform = 'scale(0.97)'}
                onMouseUp={e => e.currentTarget.style.transform = 'scale(1)'}
              >
                {busy === sev ? <Loader size={12} className="spin" /> : <Zap size={12} />}
                {m.label}
              </button>
            ))}
          </div>

          {last && (
            <div style={{
              borderTop: '1px solid var(--border)',
              padding: '10px 14px',
              fontSize: 11,
              color: last.ok ? 'var(--success)' : 'var(--accent-red)',
              display: 'flex', alignItems: 'flex-start', gap: 6,
            }}>
              {last.ok
                ? <>
                    <Check size={13} style={{ marginTop: 1, flexShrink: 0 }} />
                    <div>
                      <div>{SEV_META[last.severity].label} alert fired</div>
                      {last.location && (
                        <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2,
                                       fontFamily: 'var(--font-mono)' }}>
                          {last.location} · {last.isp || 'unknown ISP'}
                        </div>
                      )}
                    </div>
                  </>
                : <>Failed: {last.error}</>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function Topbar({ liveAlerts = [] }) {
  const [showNotifs, setShowNotifs] = useState(false);
  const unread = liveAlerts.length;

  const sevColor = (sev) => {
    const m = { critical: 'var(--critical)', high: 'var(--high)',
                 medium: 'var(--medium)', low: 'var(--low)' };
    return m[sev] || 'var(--text-secondary)';
  };

  return (
    <header style={{
      height: 'var(--topbar-height)',
      background: 'var(--bg-void)',
      borderBottom: '1px solid var(--border)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 20px',
      gap: 12,
      flexShrink: 0,
      position: 'relative',
    }}>

      <div style={{ flex: 1 }} />

      {/* Demo trigger button (next to bell) */}
      <DemoButton />

      {/* Notification bell */}
      <div style={{ position: 'relative' }}>
        <button
          onClick={() => setShowNotifs(!showNotifs)}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-secondary)', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
            width: 34, height: 34, borderRadius: 6,
            position: 'relative',
          }}
        >
          <Bell size={17} />
          {unread > 0 && (
            <span style={{
              position: 'absolute', top: 3, right: 3,
              width: 14, height: 14, borderRadius: '50%',
              background: 'var(--accent-red)',
              fontSize: 9, fontWeight: 700, color: '#fff',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: 'var(--font-mono)',
            }}>
              {unread}
            </span>
          )}
        </button>

        {/* Dropdown */}
        {showNotifs && (
          <div style={{
            position: 'absolute', top: 40, right: 0,
            width: 340,
            background: 'var(--bg-panel)',
            border: '1px solid var(--border-glow)',
            borderRadius: 6,
            zIndex: 999,
            overflow: 'hidden',
            boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
          }}>
            <div style={{
              padding: '10px 14px',
              borderBottom: '1px solid var(--border)',
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: 1, color: 'var(--text-secondary)' }}>
                LIVE ALERTS
              </span>
              <button onClick={() => setShowNotifs(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                <X size={14} />
              </button>
            </div>

            {liveAlerts.length === 0 ? (
              <div style={{ padding: '20px', color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>
                No new alerts
              </div>
            ) : (
              liveAlerts.map((alert, i) => (
                <div key={i} style={{
                  padding: '10px 14px',
                  borderBottom: '1px solid var(--border)',
                  display: 'flex', gap: 10, alignItems: 'flex-start',
                  animation: 'fade-in-up 0.2s ease',
                }}>
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: sevColor(alert.severity),
                    marginTop: 5, flexShrink: 0,
                    boxShadow: `0 0 6px ${sevColor(alert.severity)}`,
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: 'var(--text-primary)', marginBottom: 2,
                                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {alert.rule_description}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      {alert.agent_name} · {alert.severity?.toUpperCase()}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Version badge */}
      <div style={{
        fontSize: 10, fontFamily: 'var(--font-mono)',
        color: 'var(--text-muted)', letterSpacing: 1,
      }}>
        v1.0
      </div>
    </header>
  );
}
