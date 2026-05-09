import React, { useState, useEffect } from 'react';
import { Mail, Bell, Save, Send, CheckCircle, XCircle } from 'lucide-react';
import { api } from '../api';

export default function SettingsPage() {
  const [config, setConfig] = useState({
    email: '',
    min_level: 10,
    notify_fim: true,
    notify_malware: true,
    notify_sca: true,
    notify_vuln: true,
  });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saveResult, setSaveResult] = useState(null);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    api.getNotifyConfig().then(data => {
      if (data.email) setConfig(data);
    });
  }, []);

  async function handleSave() {
    setSaving(true);
    setSaveResult(null);
    try {
      await api.saveNotifyConfig(config);
      setSaveResult({ ok: true, msg: 'Notification settings saved.' });
    } catch (e) {
      setSaveResult({ ok: false, msg: 'Failed to save. Is the backend running?' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    if (!config.email) return;
    setTesting(true);
    setTestResult(null);
    try {
      const res = await api.sendTestEmail();
      if (res.status === 'sent') {
        setTestResult({ ok: true, msg: `Test email sent to ${config.email}. Check your inbox.` });
      } else {
        setTestResult({ ok: false, msg: res.reason || 'Could not send email. Check SMTP settings in .env' });
      }
    } catch (e) {
      setTestResult({ ok: false, msg: 'Failed. Backend unreachable or SMTP not configured.' });
    } finally {
      setTesting(false);
    }
  }

  const Toggle = ({ value, onChange, label, description }) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '14px 0', borderBottom: '1px solid var(--border)' }}>
      <div>
        <div style={{ fontSize: 14, color: 'var(--text-primary)', marginBottom: 2 }}>{label}</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{description}</div>
      </div>
      <div
        onClick={onChange}
        style={{
          width: 44, height: 24, borderRadius: 12, cursor: 'pointer',
          background: value ? 'var(--accent-red)' : 'var(--border)',
          position: 'relative', transition: 'background 0.2s', flexShrink: 0,
        }}
      >
        <div style={{
          position: 'absolute', top: 3, borderRadius: '50%',
          width: 18, height: 18, background: '#fff',
          transition: 'left 0.2s',
          left: value ? 23 : 3,
        }} />
      </div>
    </div>
  );

  return (
    <div className="animate-fade-in" style={{ maxWidth: 640 }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 4 }}>
          ADMINISTRATION
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>Notification Settings</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 6 }}>
          Configure email alerts so you're notified when critical events occur on your endpoints.
        </p>
      </div>

      {/* Email config */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title"><Mail size={12} style={{ display: 'inline', marginRight: 6 }} />
            Email Configuration
          </span>
        </div>
        <div style={{ padding: '20px' }}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)',
                            marginBottom: 6, fontWeight: 500 }}>
              Admin Email Address
            </label>
            <input
              type="email"
              value={config.email}
              onChange={e => setConfig({ ...config, email: e.target.value })}
              placeholder="admin@yourcompany.com"
            />
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 5 }}>
              Alert emails will be sent to this address.
              Configure SMTP credentials in your <code style={{ fontFamily: 'var(--font-mono)' }}>.env</code> file.
            </div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 12, color: 'var(--text-secondary)',
                            marginBottom: 6, fontWeight: 500 }}>
              Minimum Alert Level to Email (Wazuh scale: 1–15)
            </label>
            <select value={config.min_level} onChange={e => setConfig({ ...config, min_level: +e.target.value })}>
              <option value={7}>Level 7+ — Medium and above</option>
              <option value={10}>Level 10+ — High and above (recommended)</option>
              <option value={12}>Level 12+ — Very high and above</option>
              <option value={13}>Level 13+ — Critical only</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alert type toggles */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title">
            <Bell size={12} style={{ display: 'inline', marginRight: 6 }} />
            Alert Types
          </span>
        </div>
        <div style={{ padding: '0 20px' }}>
          <Toggle value={config.notify_malware}
                  onChange={() => setConfig({ ...config, notify_malware: !config.notify_malware })}
                  label="Malware Detection"
                  description="ClamAV findings, suspicious files, YARA matches" />
          <Toggle value={config.notify_fim}
                  onChange={() => setConfig({ ...config, notify_fim: !config.notify_fim })}
                  label="File Integrity Monitoring"
                  description="Changes to system binaries, config files, cron jobs" />
          <Toggle value={config.notify_sca}
                  onChange={() => setConfig({ ...config, notify_sca: !config.notify_sca })}
                  label="Configuration Assessment"
                  description="CIS benchmark failures, hardening issues" />
          <Toggle value={config.notify_vuln}
                  onChange={() => setConfig({ ...config, notify_vuln: !config.notify_vuln })}
                  label="Vulnerability Detection"
                  description="Critical and high CVEs found on endpoints" />
        </div>
        <div style={{ height: 8 }} />
      </div>

      {/* SMTP reminder */}
      <div style={{
        background: '#0d1a2d', border: '1px solid var(--border-glow)',
        borderRadius: 6, padding: '14px 18px', marginBottom: 20,
        fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6,
      }}>
        <strong style={{ color: 'var(--low)' }}>📧 SMTP Setup:</strong> Edit your{' '}
        <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>.env</code> file and set:
        <br />
        <code style={{ fontFamily: 'var(--font-mono)', display: 'block', marginTop: 6,
                        color: '#7fbbff', lineHeight: 1.8 }}>
          SMTP_HOST=smtp.gmail.com<br />
          SMTP_PORT=587<br />
          SMTP_USER=you@gmail.com<br />
          SMTP_PASS=your-app-password<br />
          EMAIL_FROM=watchtower@yourco.com
        </code>
        <div style={{ marginTop: 6 }}>
          For Gmail: go to Google Account → Security → App Passwords → generate one.
          Never use your real Gmail password here.
        </div>
      </div>

      {/* Buttons */}
      <div style={{ display: 'flex', gap: 10 }}>
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
          <Save size={14} />
          {saving ? 'Saving…' : 'Save Settings'}
        </button>
        <button className="btn btn-ghost" onClick={handleTest}
                disabled={testing || !config.email}>
          <Send size={14} />
          {testing ? 'Sending…' : 'Send Test Email'}
        </button>
      </div>

      {/* Result feedback */}
      {saveResult && (
        <div style={{
          marginTop: 14, display: 'flex', alignItems: 'center', gap: 8, fontSize: 13,
          color: saveResult.ok ? 'var(--success)' : 'var(--critical)',
        }}>
          {saveResult.ok ? <CheckCircle size={15} /> : <XCircle size={15} />}
          {saveResult.msg}
        </div>
      )}
      {testResult && (
        <div style={{
          marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, fontSize: 13,
          color: testResult.ok ? 'var(--success)' : 'var(--critical)',
        }}>
          {testResult.ok ? <CheckCircle size={15} /> : <XCircle size={15} />}
          {testResult.msg}
        </div>
      )}
    </div>
  );
}
