import { useState, useEffect } from 'react';
import {
  Server,
  User,
  HardDrive,
  Cpu,
  RefreshCw,
  Save,
  Check,
  RotateCcw,
} from 'lucide-react';
import {
  API_BASE,
  getPlatformSettings,
  probeBackend,
  checkBackendHealth,
  type SystemSettingsRecord,
  type BackendStatus,
} from '../services/api';

export default function Settings() {
  const [settingsData, setSettingsData] = useState<SystemSettingsRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<BackendStatus>('checking');
  const [saveSuccess, setSaveSuccess] = useState(false);

  // User Profile
  const [analystName, setAnalystName] = useState(() => localStorage.getItem('pcapman_analyst_name') || '');
  const [organization, setOrganization] = useState(() => localStorage.getItem('pcapman_organization') || '');
  const [clearance, setClearance] = useState(() => localStorage.getItem('pcapman_clearance') || '');

  // Preferences
  const [hashAlgo, setHashAlgo] = useState(() => localStorage.getItem('pcapman_hash_algo') || 'SHA-256');
  const [themeAccent, setThemeAccent] = useState(() => localStorage.getItem('pcapman_theme_accent') || 'cyan');

  const loadSettings = async () => {
    setLoading(true);
    try {
      const [data, conn] = await Promise.all([getPlatformSettings(), probeBackend()]);
      setSettingsData(data);
      setConnectionStatus(conn);
    } catch (err) {
      console.error('Failed to load settings', err);
      setLoadError(err instanceof Error ? err.message : 'Could not load platform diagnostics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleTestConnection = async () => {
    setTestingConnection(true);
    try {
      const health = await checkBackendHealth();
      setConnectionStatus(health.status === 'healthy' ? 'online' : 'offline');
    } catch {
      setConnectionStatus('offline');
    } finally {
      setTestingConnection(false);
    }
  };

  const handleSaveSettings = () => {
    localStorage.setItem('pcapman_analyst_name', analystName);
    localStorage.setItem('pcapman_organization', organization);
    localStorage.setItem('pcapman_clearance', clearance);
    localStorage.setItem('pcapman_hash_algo', hashAlgo);
    localStorage.setItem('pcapman_theme_accent', themeAccent);

    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2000);
  };

  const handleResetDefaults = () => {
    if (confirm('Reset platform settings and analyst profile to default values?')) {
      localStorage.removeItem('pcapman_analyst_name');
      localStorage.removeItem('pcapman_organization');
      localStorage.removeItem('pcapman_clearance');
      localStorage.removeItem('pcapman_hash_algo');
      localStorage.removeItem('pcapman_theme_accent');
      setAnalystName('');
      setOrganization('');
      setClearance('');
      setHashAlgo('SHA-256');
      setThemeAccent('cyan');
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Platform Settings & Diagnostics
            </h1>
            <span style={{
              fontSize: '11px',
              fontFamily: 'monospace',
              padding: '2px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(6, 182, 212, 0.15)',
              color: 'var(--color-cyan)',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              fontWeight: 600,
            }}>
              SYSTEM CONFIGURATION
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '640px' }}>
            View local backend diagnostics and update analyst profile and desktop preferences.
          </p>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={handleResetDefaults}
            style={{
              backgroundColor: '#1e293b',
              color: '#94a3b8',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '8px 14px',
              fontSize: '12px',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <RotateCcw size={14} />
            <span>Reset Defaults</span>
          </button>

          <button
            onClick={handleSaveSettings}
            style={{
              backgroundColor: saveSuccess ? '#10b981' : 'var(--color-cyan)',
              color: '#0b0f19',
              border: 'none',
              borderRadius: '8px',
              padding: '8px 18px',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'background-color 0.2s ease',
              boxShadow: '0 0 15px rgba(6, 182, 212, 0.25)',
            }}
          >
            {saveSuccess ? <Check size={16} /> : <Save size={16} />}
            <span>{saveSuccess ? 'Settings Saved!' : 'Save Settings'}</span>
          </button>
        </div>
      </div>

      {loadError && <div role="alert" style={{ color: '#fca5a5', fontSize: '13px' }}>{loadError}</div>}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
          Reading platform diagnostics...
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '20px' }}>
          {/* Section 1: Backend & Engine Connection */}
          <div style={{
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '16px',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Server size={18} style={{ color: 'var(--color-cyan)' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                Core Engine & API Service
              </h3>
            </div>

            <div>
              <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '6px' }}>
                Backend REST Endpoint
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="text"
                  readOnly
                  value={API_BASE}
                  style={{
                    flex: 1,
                    backgroundColor: '#0b0f19',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    color: '#f8fafc',
                    fontFamily: 'monospace',
                    fontSize: '13px',
                  }}
                />
                <button
                  onClick={handleTestConnection}
                  disabled={testingConnection}
                  style={{
                    backgroundColor: '#1e293b',
                    color: '#cbd5e1',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '8px 14px',
                    fontSize: '12px',
                    cursor: testingConnection ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <RefreshCw size={13} style={{ animation: testingConnection ? 'spin 1s linear infinite' : 'none' }} />
                  <span>Test</span>
                </button>
              </div>
            </div>

            {/* Health status banner */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '10px 14px',
              borderRadius: '8px',
              backgroundColor: connectionStatus === 'online' ? 'rgba(16, 185, 129, 0.08)' : 'rgba(245, 158, 11, 0.08)',
              border: `1px solid ${connectionStatus === 'online' ? 'rgba(16, 185, 129, 0.25)' : 'rgba(245, 158, 11, 0.25)'}`,
            }}>
              <span style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: connectionStatus === 'online' ? '#10b981' : '#f59e0b',
                boxShadow: connectionStatus === 'online' ? '0 0 10px #10b981' : 'none',
              }} />
              <div style={{ fontSize: '12px' }}>
                <div style={{ color: connectionStatus === 'online' ? '#34d399' : '#fbbf24', fontWeight: 600 }}>
                  {connectionStatus === 'online' ? 'FastAPI Engine Connected' : 'Backend Offline'}
                </div>
                <div style={{ color: '#94a3b8', fontSize: '11px', marginTop: '2px' }}>
                  Backend health check completed
                </div>
              </div>
            </div>

            {/* Packet parser diagnostics */}
            <div>
              <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '6px' }}>
                Packet Analysis Engine
              </label>
              <div style={{ backgroundColor: '#0b0f19', border: '1px solid #334155', borderRadius: '8px', padding: '8px 12px', color: '#cbd5e1', fontFamily: 'monospace', fontSize: '12px' }}>
                {settingsData?.tshark_detected ? settingsData.tshark_binary_path : 'Scapy streaming parser (PCAP / PCAPNG)'}
              </div>
              <p style={{ color: '#64748b', fontSize: '11px', margin: '6px 0 0 0' }}>
                Packet records are read incrementally by the local analysis backend.
              </p>
            </div>
          </div>

          {/* Section 2: Analyst Profile */}
          <div style={{
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '16px',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <User size={18} style={{ color: '#a78bfa' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                Forensic Examiner Profile
              </h3>
            </div>

            <div>
              <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '6px' }}>
                Lead Analyst Name
              </label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#0b0f19',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '8px 12px',
                  color: '#f8fafc',
                  fontSize: '13px',
                }}
              />
            </div>

            <div>
              <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '6px' }}>
                Affiliation / Lab
              </label>
              <input
                type="text"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#0b0f19',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '8px 12px',
                  color: '#f8fafc',
                  fontSize: '13px',
                }}
              />
            </div>

            <div>
              <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '6px' }}>
                Clearance / Role
              </label>
              <input
                type="text"
                value={clearance}
                onChange={(e) => setClearance(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#0b0f19',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '8px 12px',
                  color: '#f8fafc',
                  fontSize: '13px',
                }}
              />
            </div>
          </div>

          {/* Section 3: Evidence Storage & Database Ledger */}
          <div style={{
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '16px',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <HardDrive size={18} style={{ color: 'var(--color-terminal)' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                Storage Partitions & SQLite Ledger
              </h3>
            </div>

            <div>
              <div style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>Evidence Directory</div>
              <div style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #1f2937',
                borderRadius: '8px',
                padding: '8px 12px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: '#cbd5e1',
                wordBreak: 'break-all',
              }}>
                {settingsData?.evidence_directory}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>SQLite Database File</div>
              <div style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #1f2937',
                borderRadius: '8px',
                padding: '8px 12px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: '#cbd5e1',
                wordBreak: 'break-all',
                display: 'flex',
                justifyContent: 'space-between',
              }}>
                <span style={{ wordBreak: 'break-all' }}>{settingsData?.database_path || 'Unavailable'}</span>
                <span style={{ color: 'var(--color-terminal)' }}>
                  {settingsData ? (settingsData.database_size_bytes / 1024).toFixed(1) : 0} KB
                </span>
              </div>
            </div>

            <div>
              <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '6px' }}>
                Default Chain-of-Custody Hash Algorithm
              </label>
              <select
                value={hashAlgo}
                onChange={(e) => setHashAlgo(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#0b0f19',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '8px 12px',
                  color: '#f8fafc',
                  fontSize: '13px',
                }}
              >
                <option value="SHA-256">SHA-256 (NIST Recommended)</option>
                <option value="SHA-256 + MD5">Dual Hash: SHA-256 + MD5</option>
                <option value="SHA-512">SHA-512 (High Security)</option>
              </select>
            </div>
          </div>

          {/* Section 4: System Host Diagnostics */}
          <div style={{
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '16px',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Cpu size={18} style={{ color: '#f59e0b' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                Hardware & Runtime Diagnostics
              </h3>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div style={{ backgroundColor: '#0b0f19', padding: '10px 12px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>Operating System</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc', marginTop: '2px' }}>
                  {settingsData?.os_platform || 'Unavailable'}
                </div>
              </div>

              <div style={{ backgroundColor: '#0b0f19', padding: '10px 12px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>CPU Hardware</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc', marginTop: '2px' }}>
                  {settingsData?.cpu_count} logical CPUs
                </div>
              </div>

              <div style={{ backgroundColor: '#0b0f19', padding: '10px 12px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>Python Runtime</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc', marginTop: '2px' }}>
                  v{settingsData?.python_version}
                </div>
              </div>

              <div style={{ backgroundColor: '#0b0f19', padding: '10px 12px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>Engine Version</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-cyan)', marginTop: '2px' }}>
                  v{settingsData?.app_version}
                </div>
              </div>
            </div>

            <div style={{
              backgroundColor: 'rgba(6, 182, 212, 0.08)',
              border: '1px solid rgba(6, 182, 212, 0.25)',
              borderRadius: '8px',
              padding: '10px 14px',
              fontSize: '12px',
              color: '#38bdf8',
            }}>
              Zero Cloud Telemetry Guarantee: Application processes all packet streams locally with strict air-gap compliance.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
