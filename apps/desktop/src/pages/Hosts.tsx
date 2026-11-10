import { useState, useEffect } from 'react';
import {
  Globe,
  Search,
  Server,
  Laptop,
  RefreshCw,
  HardDrive,
  Copy,
  Check,
} from 'lucide-react';
import { getHosts, type HostRecord } from '../services/api';

export default function Hosts() {
  const [hosts, setHosts] = useState<HostRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedHost, setSelectedHost] = useState<HostRecord | null>(null);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  const fetchHostsData = async () => {
    setLoading(true);
    setErrorMessage('');
    try {
      const res = await getHosts(searchTerm || undefined);
      setHosts(res.hosts);
    } catch (err) {
      console.error('Failed to load hosts', err);
      setErrorMessage(err instanceof Error ? err.message : 'Could not load hosts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHostsData();
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchHostsData();
  };

  const handleCopy = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 1800);
  };

  const totalPackets = hosts.reduce((acc, h) => acc + h.packet_count, 0);
  const totalBytes = hosts.reduce((acc, h) => acc + h.bytes_total, 0);
  const hostsWithServices = hosts.filter((host) => host.open_ports.length > 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Host Intelligence & Asset Discovery
            </h1>
            <span style={{
              fontSize: '11px',
              fontFamily: 'monospace',
              padding: '2px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              fontWeight: 600,
            }}>
              PHASE 3 OPERATIONAL
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '640px' }}>
            Endpoints and observed network services derived from the analyzed capture traffic.
          </p>
        </div>

        {/* Stats */}
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Globe size={16} style={{ color: 'var(--color-cyan)' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Discovered Hosts</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>{hosts.length}</div>
            </div>
          </div>

          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={16} style={{ color: 'var(--color-cyan)' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Hosts with Observed Services</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>{hostsWithServices.length}</div>
            </div>
          </div>

          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <HardDrive size={16} style={{ color: 'var(--color-terminal)' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Network Activity</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
                {(totalBytes / 1024).toFixed(1)} KB <span style={{ fontSize: '12px', color: '#64748b', fontWeight: 400 }}>({totalPackets} pkts)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px',
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '12px',
        padding: '12px 16px',
      }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', alignItems: 'center', gap: '8px', width: '100%', maxWidth: '400px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            backgroundColor: '#0b0f19',
            border: '1px solid #334155',
            borderRadius: '8px',
            padding: '6px 12px',
            gap: '8px',
            width: '100%',
          }}>
            <Search size={15} style={{ color: '#64748b' }} />
            <input
              type="text"
              placeholder="Filter by IP, MAC, Hostname, or Role..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#f8fafc',
                fontSize: '13px',
                outline: 'none',
                width: '100%',
              }}
            />
          </div>

          <button
            type="submit"
            style={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              color: '#cbd5e1',
              borderRadius: '8px',
              padding: '7px 14px',
              fontSize: '12px',
              cursor: 'pointer',
              fontWeight: 500,
            }}
          >
            Search
          </button>
        </form>

        <button
          onClick={fetchHostsData}
          title="Refresh Host Inventory"
          style={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            color: '#94a3b8',
            borderRadius: '8px',
            padding: '8px',
            cursor: 'pointer',
          }}
        >
          <RefreshCw size={15} />
        </button>
      </div>

      {/* Host Cards Grid */}
      {errorMessage ? (
        <div role="alert" style={{ textAlign: 'center', padding: '48px', color: '#fca5a5' }}>{errorMessage}</div>
      ) : loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
          Analyzing endpoint footprints...
        </div>
      ) : hosts.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }}>
          <Globe size={36} style={{ color: '#475569', marginBottom: '10px' }} />
          <p>No host profiles match the search criteria.</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '16px' }}>
          {hosts.map((host) => {
            return (
              <div
                key={host.ip}
                onClick={() => setSelectedHost(host)}
                style={{
                  backgroundColor: '#111827',
                  border: '1px solid #1f2937',
                  borderRadius: '12px',
                  padding: '18px',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  boxShadow: 'none',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = 'var(--color-cyan)';
                  e.currentTarget.style.transform = 'translateY(-2px)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = '#1f2937';
                  e.currentTarget.style.transform = 'translateY(0)';
                }}
              >
                {/* Top Row: IP & Threat Badge */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {host.role.toLowerCase().includes('gateway') ? (
                      <Server size={18} style={{ color: 'var(--color-cyan)' }} />
                    ) : (
                      <Laptop size={18} style={{ color: '#38bdf8' }} />
                    )}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', fontFamily: 'monospace' }}>
                          {host.ip}
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopy(host.ip);
                          }}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            color: copiedIp === host.ip ? '#10b981' : '#64748b',
                            cursor: 'pointer',
                            padding: '2px',
                          }}
                        >
                          {copiedIp === host.ip ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>
                        MAC: {host.mac}
                      </div>
                    </div>
                  </div>

                  {/* Assessment state */}
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    padding: '3px 8px',
                    borderRadius: '6px',
                    backgroundColor: '#0b0f19',
                    color: '#94a3b8',
                    border: '1px solid #334155',
                  }}>
                    Not assessed
                  </span>
                </div>

                {/* Hostname & Role */}
                <div style={{ marginTop: '12px' }}>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#cbd5e1' }}>
                    {host.hostname}
                  </div>
                  <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>
                    {host.role}
                  </div>
                </div>

                {/* Open Ports */}
                <div style={{ marginTop: '14px' }}>
                  <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', marginBottom: '6px' }}>
                    Observed Services / Ports
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {host.open_ports.map((port) => (
                      <span
                        key={port}
                        style={{
                          fontSize: '11px',
                          fontFamily: 'monospace',
                          padding: '2px 6px',
                          borderRadius: '4px',
                          backgroundColor: '#0b0f19',
                          border: '1px solid #1f2937',
                          color: port === 8080 || port === 445 ? '#f87171' : '#38bdf8',
                        }}
                      >
                        :{port}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Traffic Footer */}
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginTop: '16px',
                  paddingTop: '12px',
                  borderTop: '1px solid #1f2937',
                  fontSize: '12px',
                  color: '#94a3b8',
                }}>
                  <div>
                    <span style={{ color: '#64748b' }}>Packets: </span>
                    <span style={{ color: '#f8fafc', fontWeight: 600 }}>{host.packet_count}</span>
                  </div>
                  <div>
                    <span style={{ color: '#64748b' }}>Volume: </span>
                    <span style={{ color: '#f8fafc', fontWeight: 600 }}>{(host.bytes_total / 1024).toFixed(1)} KB</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Host Profile Inspection Modal */}
      {selectedHost && (
        <div
          onClick={() => setSelectedHost(null)}
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              backgroundColor: '#111827',
              border: '1px solid #1f2937',
              borderRadius: '16px',
              maxWidth: '640px',
              width: '100%',
              padding: '24px',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Globe size={20} style={{ color: 'var(--color-cyan)' }} />
                  <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                    Endpoint Intelligence Dossier
                  </h3>
                </div>
                <div style={{ color: '#94a3b8', fontSize: '13px', marginTop: '4px' }}>
                  {selectedHost.hostname} ({selectedHost.ip})
                </div>
              </div>

              <button
                onClick={() => setSelectedHost(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#64748b',
                  fontSize: '20px',
                  cursor: 'pointer',
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={{ backgroundColor: '#0b0f19', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>IP Address</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700, fontFamily: 'monospace', fontSize: '14px', marginTop: '2px' }}>
                    {selectedHost.ip}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0b0f19', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>Hardware MAC</div>
                  <div style={{ color: '#f8fafc', fontWeight: 700, fontFamily: 'monospace', fontSize: '14px', marginTop: '2px' }}>
                    {selectedHost.mac}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0b0f19', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>First Observed</div>
                  <div style={{ color: '#cbd5e1', fontSize: '12px', marginTop: '2px' }}>
                    {new Date(selectedHost.first_seen).toLocaleTimeString()}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0b0f19', padding: '12px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>Last Activity</div>
                  <div style={{ color: '#cbd5e1', fontSize: '12px', marginTop: '2px' }}>
                    {new Date(selectedHost.last_seen).toLocaleTimeString()}
                  </div>
                </div>
              </div>

              {/* Assessment */}
              <div style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #334155',
                borderRadius: '8px',
                padding: '12px',
                fontSize: '13px',
                color: '#cbd5e1',
              }}>
                <div style={{ fontWeight: 600, marginBottom: '2px' }}>
                  Observed Endpoint: {selectedHost.role}
                </div>
                <div style={{ fontSize: '12px', color: '#cbd5e1' }}>
                  {selectedHost.packet_count} packets and {(selectedHost.bytes_sent + selectedHost.bytes_received).toLocaleString()} observed bytes in this capture. Threat reputation has not been assessed.
                </div>
              </div>
            </div>

            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedHost(null)}
                style={{
                  backgroundColor: '#1e293b',
                  color: '#f8fafc',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '8px 16px',
                  fontSize: '13px',
                  cursor: 'pointer',
                  fontWeight: 500,
                }}
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
