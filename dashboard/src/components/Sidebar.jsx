import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, AlertTriangle, Monitor,
  Shield, FolderSearch, Settings, Eye
} from 'lucide-react';

const NAV_ITEMS = [
  { to: '/overview', icon: LayoutDashboard, label: 'Overview' },
  { to: '/alerts',   icon: AlertTriangle,   label: 'Alerts' },
  { to: '/agents',   icon: Monitor,         label: 'Endpoints' },
  { to: '/attack',   icon: Shield,          label: 'ATT&CK Map' },
  { to: '/fim',      icon: FolderSearch,    label: 'File Integrity' },
  { to: '/settings', icon: Settings,        label: 'Settings' },
];

export default function Sidebar() {
  return (
    <aside style={{
      width: 'var(--sidebar-width)',
      background: 'var(--bg-void)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      flexShrink: 0,
    }}>

      {/* Logo */}
      <div style={{
        height: 'var(--topbar-height)',
        display: 'flex',
        alignItems: 'center',
        padding: '0 18px',
        borderBottom: '1px solid var(--border)',
        gap: 10,
      }}>
        <div style={{
          width: 28, height: 28,
          background: 'var(--accent-red)',
          borderRadius: 4,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Eye size={15} color="#fff" />
        </div>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: 2, color: 'var(--text-primary)' }}>
            WATCHTOWER
          </div>
          <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: 1.5, marginTop: -2 }}>
            SIEM PLATFORM
          </div>
        </div>
      </div>

      {/* Nav section label */}
      <div style={{ padding: '20px 18px 8px', fontSize: 10, letterSpacing: 2,
                    color: 'var(--text-muted)', fontWeight: 600 }}>
        DETECTION
      </div>

      {/* Nav items */}
      <nav style={{ flex: 1, padding: '0 10px' }}>
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} style={{ textDecoration: 'none' }}>
            {({ isActive }) => (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '9px 10px',
                borderRadius: 5,
                marginBottom: 2,
                background: isActive ? 'var(--accent-red-glow)' : 'transparent',
                borderLeft: isActive ? '2px solid var(--accent-red)' : '2px solid transparent',
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontSize: 13,
                fontWeight: isActive ? 600 : 400,
                transition: 'all 0.15s',
                cursor: 'pointer',
              }}
              onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'var(--bg-elevated)'; }}
              onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
              >
                <Icon size={15} />
                {label}
              </div>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Bottom status */}
      <div style={{
        padding: '12px 18px',
        borderTop: '1px solid var(--border)',
        fontSize: 11,
        color: 'var(--text-muted)',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}>
        <div className="live-dot" />
        <span>Live monitoring active</span>
      </div>
    </aside>
  );
}
