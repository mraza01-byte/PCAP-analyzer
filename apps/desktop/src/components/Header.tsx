import { Bell, Clock, Search, Terminal } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { PageKey } from '../types';

// ── Page Labels Map ────────────────────────────────────────────

const PAGE_LABELS: Record<PageKey, { title: string; subtitle: string }> = {
  home:           { title: 'Dashboard',      subtitle: 'Platform Overview & Health Telemetry' },
  captures:       { title: 'Captures',       subtitle: 'PCAP Evidence Library' },
  hosts:          { title: 'Hosts',          subtitle: 'Network Host Intelligence' },
  flows:          { title: 'Flows',          subtitle: 'Network Flow Analysis' },
  timeline:       { title: 'Timeline',       subtitle: 'Chronological Event Reconstruction' },
  investigations: { title: 'Investigations', subtitle: 'Forensic Case Management' },
  briefing:       { title: 'Briefing',       subtitle: 'Intelligence Briefing System' },
  settings:       { title: 'Settings',       subtitle: 'Platform Configuration' },
};

// ── Props ──────────────────────────────────────────────────────

interface HeaderProps {
  currentPage: PageKey;
}

// ── Component ──────────────────────────────────────────────────

export default function Header({ currentPage }: HeaderProps) {
  const [time, setTime] = useState(new Date());
  const { title, subtitle } = PAGE_LABELS[currentPage];

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const utcTime = time.toUTCString().replace(' GMT', 'Z').split(' ').slice(1).join(' ');

  return (
    <header
      id="pcap-header"
      style={{
        height: '56px',
        backgroundColor: 'var(--color-bg-surface)',
        borderBottom: '1px solid var(--color-border-dim)',
        display: 'flex',
        alignItems: 'center',
        padding: '0 20px',
        gap: '16px',
        flexShrink: 0,
        position: 'sticky',
        top: 0,
        zIndex: 20,
      }}
    >
      {/* ── Page title ───────────────────────────────────────── */}
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px' }}>
          <h1
            style={{
              margin: 0,
              fontSize: '15px',
              fontWeight: 600,
              color: 'var(--color-text-primary)',
              lineHeight: 1,
            }}
          >
            {title}
          </h1>
          <span
            style={{
              fontSize: '12px',
              color: 'var(--color-text-muted)',
            }}
          >
            {subtitle}
          </span>
        </div>
      </div>

      {/* ── Search ───────────────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          background: 'var(--color-bg-card)',
          border: '1px solid var(--color-border-dim)',
          borderRadius: '6px',
          padding: '6px 12px',
          width: '220px',
          cursor: 'not-allowed',
          opacity: 0.5,
        }}
        title="Search"
      >
        <Search size={13} style={{ color: 'var(--color-text-muted)', flexShrink: 0 }} />
        <span style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
          Search…
        </span>
      </div>

      {/* ── UTC Clock ────────────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          color: 'var(--color-text-muted)',
          fontSize: '12px',
          fontFamily: 'monospace',
          letterSpacing: '0.04em',
          minWidth: '180px',
        }}
        title="Current UTC time"
        aria-label={`Current time: ${utcTime}`}
      >
        <Clock size={13} style={{ flexShrink: 0 }} />
        <span id="header-clock">{utcTime}</span>
      </div>

      {/* ── Terminal indicator ────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          color: 'var(--color-green)',
          fontSize: '12px',
          fontFamily: 'monospace',
        }}
        title="Forensics console active"
      >
        <Terminal size={13} />
        <span>READY</span>
      </div>

      {/* ── Notifications ────────────────────────────────────── */}
      <button
        id="header-notifications"
        style={{
          background: 'none',
          border: '1px solid var(--color-border-dim)',
          borderRadius: '6px',
          padding: '6px',
          cursor: 'pointer',
          color: 'var(--color-text-muted)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: 'all 0.15s ease',
        }}
        title="Notifications — Phase 4"
        aria-label="Notifications"
      >
        <Bell size={14} />
      </button>
    </header>
  );
}
