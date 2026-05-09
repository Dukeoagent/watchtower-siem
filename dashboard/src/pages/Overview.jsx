import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { AlertTriangle, Monitor, Shield, Activity, TrendingUp } from 'lucide-react';
import { api } from '../api';

const SEV_COLORS = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--low)',
};

function KPICard({ label, value, sub, color, icon: Icon }) {
  return (
    <div className="card" style={{ padding: '18px 20px', flex: 1, minWidth: 160 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 10, letterSpacing: 1.5, color: 'var(--text-secondary)',
                        fontWeight: 600, textTransform: 'uppercase', marginBottom: 8 }}>
            {label}
          </div>
          <div style={{ fontSize: 30, fontWeight: 700, color: color || 'var(--text-primary)',
                        fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
            {value ?? '—'}
          </div>
          {sub && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>{sub}</div>}
        </div>
        {Icon && (
          <div style={{
            width: 36, height: 36, borderRadius: 6,
            background: `${color || 'var(--accent-red)'}18`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Icon size={18} color={color || 'var(--accent-red)'} />
          </div>
        )}
      </div>
    </div>
  );
}

function SeverityBadge({ sev }) {
  return <span className={`badge badge-${sev}`}>{sev}</span>;
}

// Local-timezone hour formatter for the timeline (e.g. "21:00" in viewer's TZ).
const formatLocalHour = (iso) => {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)',
                  padding: '8px 12px', borderRadius: 4, fontSize: 12 }}>
      <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>
        {formatLocalHour(label)}
      </div>
      <div style={{ color: 'var(--accent-red)', fontFamily: 'var(--font-mono)' }}>
        {payload[0].value} alerts
      </div>
    </div>
  );
};

export default function Overview() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [s, a] = await Promise.all([api.getStats(), api.getAlerts('?limit=10')]);
        setStats(s);
        setAlerts(a);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 15000); // refresh every 15s
    return () => clearInterval(interval);
  }, []);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                  height: 300, color: 'var(--text-muted)', gap: 12 }}>
      <Activity size={18} />
      Loading telemetry...
    </div>
  );

  const kd = stats?.last_24h || {};
  const pieData = [
    { name: 'Critical', value: kd.critical || 0, color: 'var(--critical)' },
    { name: 'High',     value: kd.high || 0,     color: 'var(--high)' },
    { name: 'Medium',   value: kd.medium || 0,   color: 'var(--medium)' },
    { name: 'Low',      value: kd.low || 0,       color: 'var(--low)' },
  ].filter(d => d.value > 0);

  return (
    <div className="animate-fade-in">
      {/* Page header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 4 }}>
          SECURITY OPERATIONS CENTER
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)' }}>
          Overview
        </h1>
      </div>

      {/* KPI Row */}
      <div style={{ display: 'flex', gap: 14, marginBottom: 20, flexWrap: 'wrap' }}>
        <KPICard label="Total Alerts (24h)" value={kd.total}     icon={AlertTriangle} color="var(--accent-red)" />
        <KPICard label="Critical"            value={kd.critical} icon={AlertTriangle} color="var(--critical)" />
        <KPICard label="High"                value={kd.high}     icon={TrendingUp}    color="var(--high)" />
        <KPICard label="Active Endpoints"    value={stats?.agents?.active}
                 sub={`of ${stats?.agents?.total} total`}
                 icon={Monitor} color="var(--success)" />
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 14, marginBottom: 20 }}>

        {/* Timeline */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Alert Volume — Last 24 Hours</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--success)' }}>
              <div className="live-dot" /> LIVE
            </div>
          </div>
          <div style={{ padding: '20px 10px 10px' }}>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={stats?.hourly_timeline || []}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#e8192c" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#e8192c" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="hour_iso" tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                       tickLine={false} axisLine={false} interval={3}
                       tickFormatter={formatLocalHour} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                       tickLine={false} axisLine={false} width={25} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="count" stroke="#e8192c"
                      strokeWidth={2} fill="url(#alertGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Donut */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">By Severity</span>
          </div>
          <div style={{ padding: '10px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <ResponsiveContainer width={160} height={160}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                     paddingAngle={3} dataKey="value">
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, width: '100%', padding: '0 10px' }}>
              {[
                { label: 'Critical', val: kd.critical, color: 'var(--critical)' },
                { label: 'High',     val: kd.high,     color: 'var(--high)' },
                { label: 'Medium',   val: kd.medium,   color: 'var(--medium)' },
                { label: 'Low',      val: kd.low,       color: 'var(--low)' },
              ].map(({ label, val, color }) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between',
                                          fontSize: 12, color: 'var(--text-secondary)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
                    {label}
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono)', color: color }}>{val || 0}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Alerts</span>
          <a href="/alerts" style={{ fontSize: 11, color: 'var(--accent-red)', textDecoration: 'none' }}>
            View all →
          </a>
        </div>
        <div style={{ overflow: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Description</th>
                <th>Endpoint</th>
                <th>ATT&CK TTP</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 30 }}>
                    No results found
                  </td>
                </tr>
              ) : alerts.map(a => (
                <tr key={a.id}>
                  <td><SeverityBadge sev={a.severity} /></td>
                  <td style={{ maxWidth: 280 }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.rule_description}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Rule #{a.rule_id}
                    </div>
                  </td>
                  <td>
                    <div>{a.agent_name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {a.agent_ip}
                    </div>
                  </td>
                  <td>
                    {a.ttp_id ? (
                      <div>
                        <span style={{ color: 'var(--low)',
                                        fontSize: 11, background: 'var(--low-bg)',
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
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)',
                                whiteSpace: 'nowrap' }}>
                    {new Date(a.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
