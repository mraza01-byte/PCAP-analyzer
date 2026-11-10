import {
  Activity,
  CheckCircle2,
  Database,
  FileSearch,
  Globe,
  Network,
  RefreshCw,
  Server,
  Shield,
  Wifi,
  WifiOff,
  XCircle,
  Zap,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { API_BASE, getSystemStats, probeBackend } from '../services/api';
import type { BackendStatus, SystemStats } from '../services/api';

// ── Sub-types ──────────────────────────────────────────────────

type DbStatus = 'ready' | 'checking' | 'error';
type TauriStatus = 'active' | 'inactive';

interface TelemetryState {
  tauri: TauriStatus;
  backend: BackendStatus;
  database: DbStatus;
  backendLastChecked: Date | null;
  checking: boolean;
}

// ── Status Dot ─────────────────────────────────────────────────

function StatusDot({ status }: { status: 'green' | 'amber' | 'red' }) {
  const colors = {
    green: 'var(--color-green)',
    amber: 'var(--color-amber)',
    red:   'var(--color-red)',
  };
  return (
    <span
      style={{
        display: 'inline-block',
        width: '8px',
        height: '8px',
        borderRadius: '50%',
        backgroundColor: colors[status],
        boxShadow: `0 0 6px ${colors[status]}`,
        animation: status === 'amber' ? 'pulse-glow 2s ease-in-out infinite' : undefined,
        flexShrink: 0,
      }}
    />
  );
}

// ── Telemetry Card ─────────────────────────────────────────────

interface TelemetryCardProps {
  id: string;
  icon: React.ReactNode;
  label: string;
  statusLabel: string;
  statusVariant: 'online' | 'offline' | 'checking';
  detail: string;
  accentColor: string;
}

function TelemetryCard({
  id, icon, label, statusLabel, statusVariant, detail, accentColor
}: TelemetryCardProps) {
  const dotColor = statusVariant === 'online' ? 'green' : statusVariant === 'checking' ? 'amber' : 'red';

  return (
    <div
      id={id}
      className="panel"
      style={{
        padding: '18px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        borderLeft: `3px solid ${accentColor}`,
        transition: 'all 0.2s ease',
      }}
    >
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ color: accentColor }}>{icon}</span>
          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
            {label}
          </span>
        </div>
        <span className={`badge-${statusVariant}`}>
          <StatusDot status={dotColor} />
          {statusLabel}
        </span>
      </div>

      {/* Detail */}
      <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontFamily: 'monospace' }}>
        {detail}
      </div>
    </div>
  );
}

// ── Metric Counter Card ─────────────────────────────────────────

interface MetricCounterProps {
  id: string;
  label: string;
  value: number;
  icon: React.ReactNode;
  accentColor: string;
  glowClass: string;
  description: string;
}

function MetricCounter({ id, label, value, icon, accentColor, glowClass, description }: MetricCounterProps) {
  const [displayed, setDisplayed] = useState(0);

  // Animate counter from 0 to value on mount
  useEffect(() => {
    if (value === 0) { setDisplayed(0); return; }
    let start = 0;
    const step = Math.ceil(value / 40);
    const id = setInterval(() => {
      start += step;
      if (start >= value) { setDisplayed(value); clearInterval(id); }
      else setDisplayed(start);
    }, 20);
    return () => clearInterval(id);
  }, [value]);

  return (
    <div
      id={id}
      className={`metric-card ${glowClass}`}
      style={{ padding: '20px 22px' }}
    >
      {/* Top: icon + label */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          {label}
        </span>
        <span style={{ color: accentColor, opacity: 0.7 }}>{icon}</span>
      </div>

      {/* Value */}
      <div
        style={{
          fontSize: '36px',
          fontWeight: 700,
          color: accentColor,
          fontFamily: 'monospace',
          lineHeight: 1,
          marginBottom: '8px',
          letterSpacing: '-0.02em',
        }}
      >
        {displayed.toLocaleString()}
      </div>

      {/* Description */}
      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
        {description}
      </div>
    </div>
  );
}

// ── Phase Notice ────────────────────────────────────────────────

function PhaseNotice() {
  return (
    <div
      id="phase-notice"
      style={{
        padding: '14px 18px',
        background: 'linear-gradient(90deg, rgba(6,182,212,0.06), rgba(16,185,129,0.04))',
        border: '1px solid rgba(6, 182, 212, 0.2)',
        borderRadius: '8px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
      }}
    >
      <Zap size={16} style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
      <div>
        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-cyan)', marginBottom: '3px' }}>
          PCAP-MAN — Network Forensics
        </div>
        <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', lineHeight: 1.5 }}>
          Upload captures, inspect observed hosts and flows, reconstruct packet-time events, and track investigations using the local analysis backend.
        </div>
      </div>
    </div>
  );
}

// ── Main Home Page ─────────────────────────────────────────────

export default function Home() {
  const [stats, setStats] = useState<SystemStats>({ captures: 0, hosts: 0, flows: 0, investigations: 0 });
  const [statsError, setStatsError] = useState('');
  const [telemetry, setTelemetry] = useState<TelemetryState>({
    tauri: 'inactive',
    backend: 'checking',
    database: 'checking',
    backendLastChecked: null,
    checking: true,
  });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Detect Tauri runtime ──────────────────────────────────────
  const detectTauri = useCallback((): TauriStatus => {
    return typeof window !== 'undefined' &&
      (window as unknown as { __TAURI__?: unknown }).__TAURI__ !== undefined
      ? 'active'
      : 'inactive';
  }, []);

  // ── Check backend ─────────────────────────────────────────────
  const checkBackend = useCallback(async () => {
    setTelemetry((prev) => ({ ...prev, checking: true, backend: 'checking' }));
    const status = await probeBackend();
    const dbStatus: DbStatus = status === 'online' ? 'ready' : 'checking';
    setTelemetry((prev) => ({
      ...prev,
      backend: status,
      database: dbStatus,
      backendLastChecked: new Date(),
      checking: false,
    }));
  }, []);

  // ── Initial load ──────────────────────────────────────────────
  useEffect(() => {
    const init = async () => {
      const tauriStatus = detectTauri();
      setTelemetry((prev) => ({ ...prev, tauri: tauriStatus }));

      const [, fetchedStats] = await Promise.all([checkBackend(), getSystemStats().then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      )]);
      if ('value' in fetchedStats) {
        setStats(fetchedStats.value);
        setStatsError('');
      } else {
        setStatsError(fetchedStats.error instanceof Error ? fetchedStats.error.message : 'System statistics are unavailable');
      }
    };
    init();

    // Poll backend every 30 seconds
    pollRef.current = setInterval(checkBackend, 30_000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [checkBackend, detectTauri]);

  // ── Derived values ────────────────────────────────────────────
  const tauriLabel    = telemetry.tauri    === 'active'   ? 'Active'   : 'Web Mode';
  const tauriVariant  = telemetry.tauri    === 'active'   ? 'online'   : 'checking';
  const backendLabel  = telemetry.backend  === 'online'   ? 'Online'   : telemetry.backend === 'checking' ? 'Connecting' : 'Offline';
  const backendVariant: 'online' | 'offline' | 'checking' =
    telemetry.backend === 'online' ? 'online' : telemetry.backend === 'checking' ? 'checking' : 'offline';
  const dbLabel   = telemetry.database === 'ready'    ? 'Ready'    : 'Pending';
  const dbVariant = telemetry.database === 'ready'    ? 'online'   : 'checking';

  const lastCheckedStr = telemetry.backendLastChecked
    ? `Last probe: ${telemetry.backendLastChecked.toLocaleTimeString()}`
    : 'Probing connection…';

  return (
    <div
      id="home-page"
      className="animate-fade-in-up"
      style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1200px' }}
    >
      {statsError && <div role="alert" style={{ color: '#fca5a5', fontSize: '13px' }}>{statsError}</div>}
      {/* ── Hero Branding ───────────────────────────────────── */}
      <div
        id="home-hero"
        style={{
          padding: '28px 32px',
          background: 'linear-gradient(135deg, rgba(6,182,212,0.07) 0%, rgba(16,185,129,0.05) 50%, rgba(11,15,25,0) 100%)',
          border: '1px solid var(--color-border-dim)',
          borderRadius: '12px',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Decorative grid lines */}
        <div
          aria-hidden="true"
          style={{
            position: 'absolute', inset: 0,
            backgroundImage: 'linear-gradient(rgba(6,182,212,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.04) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
            pointerEvents: 'none',
          }}
        />

        {/* Decorative corner accent */}
        <div
          aria-hidden="true"
          style={{
            position: 'absolute', top: 0, right: 0,
            width: '200px', height: '200px',
            background: 'radial-gradient(circle at top right, rgba(6,182,212,0.08), transparent 70%)',
            pointerEvents: 'none',
          }}
        />

        <div style={{ position: 'relative', zIndex: 1 }}>
          {/* Badge */}
          <div style={{ marginBottom: '14px' }}>
            <span
              style={{
                fontSize: '11px',
                fontWeight: 600,
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
                color: 'var(--color-cyan)',
                background: 'rgba(6, 182, 212, 0.1)',
                border: '1px solid rgba(6, 182, 212, 0.25)',
                borderRadius: '20px',
                padding: '3px 12px',
              }}
            >
              Network Forensics Platform
            </span>
          </div>

          {/* Title */}
          <h2
            style={{
              margin: '0 0 10px',
              fontSize: '32px',
              fontWeight: 800,
              letterSpacing: '-0.02em',
              lineHeight: 1.1,
            }}
          >
            <span style={{ color: 'var(--color-text-primary)' }}>PCAP</span>
            <span className="gradient-text-cyber">-MAN</span>
          </h2>

          {/* Subtitle */}
          <p
            style={{
              margin: '0 0 20px',
              fontSize: '15px',
              color: 'var(--color-text-secondary)',
              maxWidth: '560px',
              lineHeight: 1.65,
            }}
          >
            Entity-Centric Network Forensics — transform raw packet captures into
            structured intelligence: hosts, flows, timelines, and investigations.
          </p>

          {/* Tags */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {[
              { label: 'PCAP / PCAPNG',   color: 'var(--color-cyan)' },
              { label: 'Host Discovery',  color: 'var(--color-green)' },
              { label: 'Flow Analysis',   color: 'var(--color-violet)' },
              { label: 'Threat Hunting',  color: 'var(--color-amber)' },
              { label: 'Local-First',     color: 'var(--color-text-muted)' },
            ].map(({ label, color }) => (
              <span
                key={label}
                style={{
                  fontSize: '11px',
                  fontWeight: 500,
                  color,
                  background: 'var(--color-bg-elevated)',
                  border: '1px solid var(--color-border-dim)',
                  borderRadius: '4px',
                  padding: '3px 8px',
                  fontFamily: 'monospace',
                }}
              >
                {label}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── Telemetry Grid ──────────────────────────────────── */}
      <section aria-labelledby="telemetry-heading">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <h2
            id="telemetry-heading"
            style={{ margin: 0, fontSize: '13px', fontWeight: 600, color: 'var(--color-text-secondary)', letterSpacing: '0.06em', textTransform: 'uppercase' }}
          >
            System Telemetry
          </h2>
          <button
            id="refresh-telemetry"
            onClick={checkBackend}
            disabled={telemetry.checking}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '12px',
              color: 'var(--color-text-muted)',
              background: 'none',
              border: '1px solid var(--color-border-dim)',
              borderRadius: '6px',
              padding: '5px 10px',
              cursor: telemetry.checking ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s ease',
              opacity: telemetry.checking ? 0.6 : 1,
            }}
            aria-label="Refresh telemetry"
          >
            <RefreshCw
              size={12}
              style={{
                animation: telemetry.checking ? 'spin 1s linear infinite' : undefined,
              }}
            />
            Refresh
          </button>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '14px',
          }}
        >
          {/* Tauri Runtime */}
          <TelemetryCard
            id="telemetry-tauri"
            icon={<Zap size={16} />}
            label="Desktop Runtime"
            statusLabel={tauriLabel}
            statusVariant={tauriVariant}
            detail="Tauri v2 — Rust Core / WebView2"
            accentColor="var(--color-cyan)"
          />

          {/* Backend */}
          <TelemetryCard
            id="telemetry-backend"
            icon={<Server size={16} />}
            label="Backend Service"
            statusLabel={backendLabel}
            statusVariant={backendVariant}
            detail={`FastAPI @ ${API_BASE}  ·  ${lastCheckedStr}`}
            accentColor={
              backendVariant === 'online'   ? 'var(--color-green)' :
              backendVariant === 'checking' ? 'var(--color-amber)' :
              'var(--color-red)'
            }
          />

          {/* Database */}
          <TelemetryCard
            id="telemetry-database"
            icon={<Database size={16} />}
            label="Database Layer"
            statusLabel={dbLabel}
            statusVariant={dbVariant}
            detail="SQLite · Alembic migrations · ORM ready"
            accentColor={dbVariant === 'online' ? 'var(--color-green)' : 'var(--color-amber)'}
          />
        </div>
      </section>

      {/* ── Metric Counters ─────────────────────────────────── */}
      <section aria-labelledby="metrics-heading">
        <h2
          id="metrics-heading"
          style={{ margin: '0 0 14px', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-secondary)', letterSpacing: '0.06em', textTransform: 'uppercase' }}
        >
          Investigation Metrics
        </h2>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '14px',
          }}
        >
          <MetricCounter
            id="metric-captures"
            label="Captures"
            value={stats.captures}
            icon={<FileSearch size={18} />}
            accentColor="var(--color-cyan)"
            glowClass="glow-cyan"
            description="PCAP evidence files registered"
          />
          <MetricCounter
            id="metric-hosts"
            label="Hosts"
            value={stats.hosts}
            icon={<Globe size={18} />}
            accentColor="var(--color-green)"
            glowClass="glow-green"
            description="Unique network endpoints discovered"
          />
          <MetricCounter
            id="metric-flows"
            label="Flows"
            value={stats.flows}
            icon={<Network size={18} />}
            accentColor="var(--color-violet)"
            glowClass="glow-violet"
            description="Network conversations extracted"
          />
          <MetricCounter
            id="metric-investigations"
            label="Investigations"
            value={stats.investigations}
            icon={<Shield size={18} />}
            accentColor="var(--color-amber)"
            glowClass="glow-amber"
            description="Active forensic case files"
          />
        </div>
      </section>

      {/* ── Platform Readiness ──────────────────────────────── */}
      <section aria-labelledby="readiness-heading">
        <h2
          id="readiness-heading"
          style={{ margin: '0 0 14px', fontSize: '13px', fontWeight: 600, color: 'var(--color-text-secondary)', letterSpacing: '0.06em', textTransform: 'uppercase' }}
        >
          Platform Readiness
        </h2>

        <div className="panel" style={{ padding: '20px 24px' }}>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: '12px',
            }}
          >
            {[
              { label: 'Desktop Application',  done: true,  icon: CheckCircle2 },
              { label: 'Navigation & Routing',  done: true,  icon: CheckCircle2 },
              { label: 'Dark Theme Applied',    done: true,  icon: CheckCircle2 },
              { label: 'API Service Layer',     done: true,  icon: CheckCircle2 },
              { label: 'FastAPI Backend',       done: telemetry.backend === 'online',  icon: telemetry.backend === 'online' ? CheckCircle2 : Activity },
              { label: 'SQLite Initialized',    done: telemetry.database === 'ready',  icon: telemetry.database === 'ready' ? CheckCircle2 : Activity },
              { label: 'PCAP Import Engine',    done: false, icon: XCircle },
              { label: 'Network Intelligence',  done: false, icon: XCircle },
            ].map(({ label, done, icon: Icon }) => (
              <div
                key={label}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  background: done ? 'rgba(16,185,129,0.05)' : 'var(--color-bg-elevated)',
                  border: `1px solid ${done ? 'rgba(16,185,129,0.15)' : 'var(--color-border-dim)'}`,
                }}
              >
                <Icon
                  size={14}
                  style={{
                    color: done ? 'var(--color-green)' : 'var(--color-text-dim)',
                    flexShrink: 0,
                  }}
                />
                <span
                  style={{
                    fontSize: '13px',
                    color: done ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
                    fontWeight: done ? 500 : 400,
                  }}
                >
                  {label}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Phase Notice ────────────────────────────────────── */}
      <PhaseNotice />

      {/* Connectivity visual indicator when backend is offline */}
      {telemetry.backend === 'offline' && (
        <div
          id="backend-offline-notice"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '14px 18px',
            background: 'var(--color-red-dim)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '8px',
          }}
          role="alert"
        >
          <WifiOff size={16} style={{ color: 'var(--color-red)', flexShrink: 0 }} />
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-red)', marginBottom: '3px' }}>
              Backend Unreachable
            </div>
            <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
              FastAPI server is not responding at <span className="mono">{API_BASE}</span>.
              Start the backend with <span className="mono">uvicorn app.main:app --reload</span>.
            </div>
          </div>
        </div>
      )}

      {telemetry.backend === 'online' && (
        <div
          id="backend-online-notice"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '12px 18px',
            background: 'rgba(16, 185, 129, 0.05)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            borderRadius: '8px',
          }}
        >
          <Wifi size={15} style={{ color: 'var(--color-green)', flexShrink: 0 }} />
          <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
            Backend connected — PCAP-MAN platform is fully operational.
          </span>
        </div>
      )}
    </div>
  );
}
