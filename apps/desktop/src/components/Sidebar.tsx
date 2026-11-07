import {
  Activity,
  Briefcase,
  ChevronRight,
  Database,
  FileSearch,
  Globe,
  Home,
  Network,
  Settings,
  Shield,
} from 'lucide-react';
import type { PageKey } from '../types';

// ── Nav Configuration ──────────────────────────────────────────

interface NavEntry {
  key: PageKey;
  label: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  phase: number;
  implemented: boolean;
  group: 'core' | 'analysis' | 'system';
}

const NAV_ENTRIES: NavEntry[] = [
  // Core
  { key: 'home',           label: 'Dashboard',      icon: Home,       phase: 1, implemented: true,  group: 'core' },
  { key: 'captures',       label: 'Captures',       icon: FileSearch, phase: 2, implemented: false, group: 'core' },
  // Analysis
  { key: 'hosts',          label: 'Hosts',          icon: Globe,      phase: 3, implemented: false, group: 'analysis' },
  { key: 'flows',          label: 'Flows',          icon: Network,    phase: 3, implemented: false, group: 'analysis' },
  { key: 'timeline',       label: 'Timeline',       icon: Activity,   phase: 3, implemented: false, group: 'analysis' },
  // Investigations
  { key: 'investigations', label: 'Investigations', icon: Shield,     phase: 4, implemented: false, group: 'analysis' },
  { key: 'briefing',       label: 'Briefing',       icon: Briefcase,  phase: 6, implemented: false, group: 'analysis' },
  // System
  { key: 'settings',      label: 'Settings',        icon: Settings,   phase: 1, implemented: false, group: 'system' },
];

const GROUPS = [
  { key: 'core',     label: 'PLATFORM' },
  { key: 'analysis', label: 'INTELLIGENCE' },
  { key: 'system',   label: 'SYSTEM' },
] as const;

// ── Props ──────────────────────────────────────────────────────

interface SidebarProps {
  currentPage: PageKey;
  onNavigate: (page: PageKey) => void;
}

// ── Component ──────────────────────────────────────────────────

export default function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  return (
    <aside
      id="pcap-sidebar"
      style={{
        width: '220px',
        minHeight: '100vh',
        backgroundColor: 'var(--color-bg-base)',
        borderRight: '1px solid var(--color-border-dim)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        position: 'relative',
        zIndex: 10,
      }}
    >
      {/* ── Logo / Branding ──────────────────────────────────── */}
      <div
        style={{
          padding: '20px 16px 16px',
          borderBottom: '1px solid var(--color-border-dim)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Hex icon */}
          <div
            style={{
              width: '34px',
              height: '34px',
              background: 'linear-gradient(135deg, #06b6d4, #10b981)',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: '0 0 12px rgba(6, 182, 212, 0.35)',
            }}
          >
            <Database size={16} style={{ color: '#0b0f19' }} />
          </div>
          <div>
            <div
              style={{
                fontSize: '15px',
                fontWeight: 700,
                letterSpacing: '0.02em',
                color: 'var(--color-text-primary)',
                lineHeight: 1.1,
              }}
            >
              PCAP<span style={{ color: 'var(--color-cyan)' }}>-MAN</span>
            </div>
            <div
              style={{
                fontSize: '10px',
                color: 'var(--color-text-muted)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginTop: '2px',
              }}
            >
              Forensics Platform
            </div>
          </div>
        </div>
      </div>

      {/* ── Navigation ───────────────────────────────────────── */}
      <nav
        style={{ flex: 1, padding: '12px 10px', overflowY: 'auto' }}
        aria-label="Primary navigation"
      >
        {GROUPS.map((group) => {
          const entries = NAV_ENTRIES.filter((e) => e.group === group.key);
          return (
            <div key={group.key} style={{ marginBottom: '20px' }}>
              {/* Group label */}
              <div
                style={{
                  fontSize: '10px',
                  fontWeight: 600,
                  letterSpacing: '0.12em',
                  color: 'var(--color-text-dim)',
                  padding: '0 10px',
                  marginBottom: '4px',
                }}
              >
                {group.label}
              </div>

              {/* Nav entries */}
              {entries.map((entry) => {
                const Icon = entry.icon;
                const isActive = currentPage === entry.key;
                const isDisabled = !entry.implemented;

                return (
                  <button
                    key={entry.key}
                    id={`nav-${entry.key}`}
                    className={`nav-item${isActive ? ' active' : ''}`}
                    onClick={() => onNavigate(entry.key)}
                    disabled={false}
                    style={{
                      width: '100%',
                      background: 'none',
                      border: 'none',
                      textAlign: 'left',
                      opacity: isDisabled && !isActive ? 0.55 : 1,
                    }}
                    aria-current={isActive ? 'page' : undefined}
                    title={
                      isDisabled ? `Phase ${entry.phase} — Not yet implemented` : entry.label
                    }
                  >
                    <Icon size={15} />
                    <span style={{ flex: 1 }}>{entry.label}</span>
                    {!entry.implemented && (
                      <span
                        style={{
                          fontSize: '9px',
                          fontWeight: 600,
                          color: 'var(--color-text-dim)',
                          background: 'var(--color-bg-elevated)',
                          padding: '1px 5px',
                          borderRadius: '10px',
                          letterSpacing: '0.06em',
                        }}
                      >
                        P{entry.phase}
                      </span>
                    )}
                    {isActive && !isDisabled && (
                      <ChevronRight size={12} style={{ opacity: 0.6 }} />
                    )}
                  </button>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* ── Footer ───────────────────────────────────────────── */}
      <div
        style={{
          padding: '12px 16px',
          borderTop: '1px solid var(--color-border-dim)',
        }}
      >
        <div
          style={{
            fontSize: '10px',
            color: 'var(--color-text-dim)',
            fontFamily: 'monospace',
          }}
        >
          <div>Phase 1 — Foundation</div>
          <div style={{ color: 'var(--color-text-muted)', marginTop: '2px' }}>
            v0.1.0-alpha
          </div>
        </div>
      </div>
    </aside>
  );
}
