import { useState, useEffect } from 'react';
import {
  Layers,
  Search,
  Globe,
  Lock,
  Award,
  RefreshCw,
  Copy,
  Check,
  ShieldAlert,
  FileCode,
  ShieldCheck,
} from 'lucide-react';
import {
  getDnsRecords,
  getHttpRequests,
  getTlsRecords,
  getCertificates,
  getProtocolStats,
  type DnsRecord,
  type HttpRequestRecord,
  type TlsRecord,
  type CertificateRecord,
  type ProtocolStatsRecord,
} from '../services/api';

type TabKey = 'dns' | 'http' | 'tls' | 'certificates';

export default function Protocols() {
  const [activeTab, setActiveTab] = useState<TabKey>('dns');
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Data states
  const [dnsRecords, setDnsRecords] = useState<DnsRecord[]>([]);
  const [httpRequests, setHttpRequests] = useState<HttpRequestRecord[]>([]);
  const [tlsRecords, setTlsRecords] = useState<TlsRecord[]>([]);
  const [certificates, setCertificates] = useState<CertificateRecord[]>([]);
  const [stats, setStats] = useState<ProtocolStatsRecord | null>(null);

  // Filter states
  const [dnsTypeFilter, setDnsTypeFilter] = useState<string>('ALL');
  const [httpMethodFilter, setHttpMethodFilter] = useState<string>('ALL');
  const [tlsVersionFilter, setTlsVersionFilter] = useState<string>('ALL');
  const [certFilter, setCertFilter] = useState<string>('ALL'); // ALL, SELF_SIGNED, CA

  // Modal inspection states
  const [selectedDns, setSelectedDns] = useState<DnsRecord | null>(null);
  const [selectedHttp, setSelectedHttp] = useState<HttpRequestRecord | null>(null);
  const [selectedTls, setSelectedTls] = useState<TlsRecord | null>(null);
  const [selectedCert, setSelectedCert] = useState<CertificateRecord | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fetchProtocolData = async () => {
    setLoading(true);
    setErrorMessage('');
    try {
      const [dnsData, httpData, tlsData, certData, statsData] = await Promise.all([
        getDnsRecords({
          search: searchTerm || undefined,
          queryType: dnsTypeFilter !== 'ALL' ? dnsTypeFilter : undefined,
        }),
        getHttpRequests({
          search: searchTerm || undefined,
          method: httpMethodFilter !== 'ALL' ? httpMethodFilter : undefined,
        }),
        getTlsRecords({
          search: searchTerm || undefined,
          version: tlsVersionFilter !== 'ALL' ? tlsVersionFilter : undefined,
        }),
        getCertificates({
          search: searchTerm || undefined,
          selfSigned: certFilter === 'SELF_SIGNED' ? true : certFilter === 'CA' ? false : undefined,
        }),
        getProtocolStats(),
      ]);

      setDnsRecords(dnsData);
      setHttpRequests(httpData);
      setTlsRecords(tlsData);
      setCertificates(certData);
      setStats(statsData);
    } catch (err) {
      console.error('Failed to load protocol data', err);
      setErrorMessage(err instanceof Error ? err.message : 'Could not load protocol intelligence data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProtocolData();
  }, [dnsTypeFilter, httpMethodFilter, tlsVersionFilter, certFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchProtocolData();
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(text);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const parseAnswers = (raw?: string | null): string[] => {
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
      return [raw];
    } catch {
      return [raw];
    }
  };

  const parseSans = (raw?: string | null): string[] => {
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
      return [raw];
    } catch {
      return [raw];
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Protocol Intelligence & Deep Packet Inspection
            </h1>
            <span style={{
              fontSize: '11px',
              fontFamily: 'monospace',
              padding: '2px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(6, 182, 212, 0.15)',
              color: '#22d3ee',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              fontWeight: 600,
            }}>
              PHASE 3 OPERATIONAL
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '720px' }}>
            Extracts, decodes, and categorizes high-value application layer protocols including DNS queries, cleartext HTTP requests, TLS handshake metadata, and X.509 certificate chains.
          </p>
        </div>

        {/* Quick KPI Badges */}
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Globe size={18} style={{ color: '#38bdf8' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>DNS Records</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
                {stats?.total_dns ?? dnsRecords.length}
              </div>
            </div>
          </div>

          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileCode size={18} style={{ color: '#34d399' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>HTTP Requests</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
                {stats?.total_http ?? httpRequests.length}
              </div>
            </div>
          </div>

          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Lock size={18} style={{ color: '#a78bfa' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>TLS Sessions</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
                {stats?.total_tls ?? tlsRecords.length}
              </div>
            </div>
          </div>

          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Award size={18} style={{ color: '#fbbf24' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Certificates</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>
                {stats?.total_certificates ?? certificates.length}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Protocol Categorization & Traffic Distribution Section */}
      {stats && stats.protocol_distribution.length > 0 && (
        <div style={{
          backgroundColor: '#111827',
          border: '1px solid #1f2937',
          borderRadius: '12px',
          padding: '16px 20px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={16} style={{ color: '#22d3ee' }} />
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#f8fafc', margin: 0, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Protocol Traffic Categorization & Distribution
              </h3>
            </div>
            <span style={{ fontSize: '12px', color: '#94a3b8' }}>
              {stats.total_flows} conversation flows classified
            </span>
          </div>

          {/* Categorization Bar */}
          <div style={{
            display: 'flex',
            height: '10px',
            borderRadius: '5px',
            overflow: 'hidden',
            backgroundColor: '#1f2937',
            marginBottom: '16px',
          }}>
            {stats.protocol_distribution.map((item, idx) => {
              const colors = ['#22d3ee', '#8b5cf6', '#10b981', '#f59e0b', '#ec4899', '#6366f1', '#64748b'];
              const bg = colors[idx % colors.length];
              return (
                <div
                  key={idx}
                  title={`${item.category} (${item.application}): ${item.percentage}%`}
                  style={{
                    width: `${Math.max(item.percentage, 1)}%`,
                    backgroundColor: bg,
                    transition: 'width 0.3s ease',
                  }}
                />
              );
            })}
          </div>

          {/* Categories Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(210px, 1fr))', gap: '12px' }}>
            {stats.protocol_distribution.slice(0, 6).map((item, idx) => {
              const colors = ['#22d3ee', '#8b5cf6', '#10b981', '#f59e0b', '#ec4899', '#6366f1'];
              const accent = colors[idx % colors.length];
              return (
                <div
                  key={idx}
                  style={{
                    backgroundColor: '#0b0f19',
                    border: '1px solid #1f2937',
                    borderRadius: '8px',
                    padding: '10px 14px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '11px', color: accent, fontWeight: 700 }}>
                      {item.application}
                    </span>
                    <span style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace' }}>
                      {item.percentage}%
                    </span>
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>
                    {item.category}
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748b' }}>
                    {item.flow_count} flows • {(item.byte_count / 1024).toFixed(1)} KB
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Control Bar: Protocol Tabs & Filtering */}
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
        {/* Navigation Tabs */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button
            onClick={() => setActiveTab('dns')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: activeTab === 'dns' ? '#0284c7' : '#1e293b',
              color: activeTab === 'dns' ? '#ffffff' : '#94a3b8',
              border: `1px solid ${activeTab === 'dns' ? '#0284c7' : '#334155'}`,
              borderRadius: '6px',
              padding: '6px 14px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <Globe size={14} />
            <span>DNS Records ({dnsRecords.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('http')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: activeTab === 'http' ? '#059669' : '#1e293b',
              color: activeTab === 'http' ? '#ffffff' : '#94a3b8',
              border: `1px solid ${activeTab === 'http' ? '#059669' : '#334155'}`,
              borderRadius: '6px',
              padding: '6px 14px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <FileCode size={14} />
            <span>HTTP Transactions ({httpRequests.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('tls')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: activeTab === 'tls' ? '#7c3aed' : '#1e293b',
              color: activeTab === 'tls' ? '#ffffff' : '#94a3b8',
              border: `1px solid ${activeTab === 'tls' ? '#7c3aed' : '#334155'}`,
              borderRadius: '6px',
              padding: '6px 14px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <Lock size={14} />
            <span>TLS Handshakes ({tlsRecords.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('certificates')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: activeTab === 'certificates' ? '#d97706' : '#1e293b',
              color: activeTab === 'certificates' ? '#ffffff' : '#94a3b8',
              border: `1px solid ${activeTab === 'certificates' ? '#d97706' : '#334155'}`,
              borderRadius: '6px',
              padding: '6px 14px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <Award size={14} />
            <span>X.509 Certificates ({certificates.length})</span>
          </button>
        </div>

        {/* Tab Specific Filters & Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          {activeTab === 'dns' && (
            <select
              value={dnsTypeFilter}
              onChange={(e) => setDnsTypeFilter(e.target.value)}
              style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #334155',
                color: '#cbd5e1',
                borderRadius: '8px',
                padding: '6px 10px',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="ALL">All Types</option>
              <option value="A">A (IPv4)</option>
              <option value="AAAA">AAAA (IPv6)</option>
              <option value="CNAME">CNAME</option>
              <option value="PTR">PTR</option>
              <option value="TXT">TXT</option>
              <option value="MX">MX</option>
            </select>
          )}

          {activeTab === 'http' && (
            <select
              value={httpMethodFilter}
              onChange={(e) => setHttpMethodFilter(e.target.value)}
              style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #334155',
                color: '#cbd5e1',
                borderRadius: '8px',
                padding: '6px 10px',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="ALL">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="HEAD">HEAD</option>
            </select>
          )}

          {activeTab === 'tls' && (
            <select
              value={tlsVersionFilter}
              onChange={(e) => setTlsVersionFilter(e.target.value)}
              style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #334155',
                color: '#cbd5e1',
                borderRadius: '8px',
                padding: '6px 10px',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="ALL">All Versions</option>
              <option value="TLS 1.3">TLS 1.3</option>
              <option value="TLS 1.2">TLS 1.2</option>
              <option value="TLS 1.1">TLS 1.1</option>
              <option value="TLS 1.0">TLS 1.0</option>
            </select>
          )}

          {activeTab === 'certificates' && (
            <select
              value={certFilter}
              onChange={(e) => setCertFilter(e.target.value)}
              style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #334155',
                color: '#cbd5e1',
                borderRadius: '8px',
                padding: '6px 10px',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="ALL">All Certificates</option>
              <option value="SELF_SIGNED">Self-Signed Only</option>
              <option value="CA">CA Issued Only</option>
            </select>
          )}

          {/* Search Form */}
          <form onSubmit={handleSearch} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              backgroundColor: '#0b0f19',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '6px 12px',
              gap: '8px',
            }}>
              <Search size={14} style={{ color: '#64748b' }} />
              <input
                type="text"
                placeholder="Search domain, host, cipher..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#f8fafc',
                  fontSize: '12px',
                  outline: 'none',
                  width: '180px',
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
                padding: '7px 12px',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              Filter
            </button>

            <button
              type="button"
              onClick={() => {
                setSearchTerm('');
                setDnsTypeFilter('ALL');
                setHttpMethodFilter('ALL');
                setTlsVersionFilter('ALL');
                setCertFilter('ALL');
                fetchProtocolData();
              }}
              title="Reset Filters"
              style={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                color: '#94a3b8',
                borderRadius: '8px',
                padding: '7px 10px',
                cursor: 'pointer',
              }}
            >
              <RefreshCw size={14} />
            </button>
          </form>
        </div>
      </div>

      {/* Main Protocol Content Table */}
      <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', overflow: 'hidden' }}>
        {errorMessage ? (
          <div role="alert" style={{ textAlign: 'center', padding: '48px', color: '#fca5a5' }}>{errorMessage}</div>
        ) : loading ? (
          <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
            Extracting protocol metadata...
          </div>
        ) : (
          <div>
            {/* 1. DNS TAB */}
            {activeTab === 'dns' && (
              dnsRecords.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }}>
                  <Globe size={36} style={{ color: '#475569', marginBottom: '10px' }} />
                  <p>No DNS records found for the selected criteria.</p>
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #1f2937', backgroundColor: '#0e1422', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                        <th style={{ padding: '12px 16px' }}>Query Name</th>
                        <th style={{ padding: '12px 12px' }}>Type</th>
                        <th style={{ padding: '12px 12px' }}>Response Code</th>
                        <th style={{ padding: '12px 16px' }}>Answers / Resolution</th>
                        <th style={{ padding: '12px 12px' }}>TTL</th>
                        <th style={{ padding: '12px 16px' }}>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dnsRecords.map((dns) => {
                        const answers = parseAnswers(dns.answers);
                        return (
                          <tr
                            key={dns.id}
                            onClick={() => setSelectedDns(dns)}
                            style={{
                              borderBottom: '1px solid rgba(31, 41, 55, 0.6)',
                              cursor: 'pointer',
                              transition: 'background-color 0.15s ease',
                            }}
                            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.03)')}
                            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                          >
                            <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontWeight: 600, color: '#f8fafc' }}>
                              {dns.query_name}
                            </td>
                            <td style={{ padding: '12px 12px' }}>
                              <span style={{
                                fontSize: '11px',
                                fontFamily: 'monospace',
                                fontWeight: 700,
                                padding: '2px 6px',
                                borderRadius: '4px',
                                backgroundColor: 'rgba(56, 189, 248, 0.15)',
                                color: '#38bdf8',
                              }}>
                                {dns.query_type}
                              </span>
                            </td>
                            <td style={{ padding: '12px 12px' }}>
                              <span style={{
                                fontSize: '11px',
                                fontFamily: 'monospace',
                                fontWeight: 600,
                                padding: '2px 6px',
                                borderRadius: '4px',
                                backgroundColor: dns.response_code === 'NOERROR' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                                color: dns.response_code === 'NOERROR' ? '#34d399' : '#f87171',
                              }}>
                                {dns.response_code || 'QUERY'}
                              </span>
                            </td>
                            <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: '#cbd5e1' }}>
                              {answers.length > 0 ? answers.slice(0, 3).join(', ') : '-'}
                              {answers.length > 3 && ` (+${answers.length - 3} more)`}
                            </td>
                            <td style={{ padding: '12px 12px', color: '#94a3b8', fontFamily: 'monospace' }}>
                              {dns.ttl !== null && dns.ttl !== undefined ? `${dns.ttl}s` : '-'}
                            </td>
                            <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px', fontFamily: 'monospace' }}>
                              {new Date(dns.timestamp).toLocaleTimeString()}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )
            )}

            {/* 2. HTTP TAB */}
            {activeTab === 'http' && (
              httpRequests.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }}>
                  <FileCode size={36} style={{ color: '#475569', marginBottom: '10px' }} />
                  <p>No HTTP transactions found for the selected criteria.</p>
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #1f2937', backgroundColor: '#0e1422', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                        <th style={{ padding: '12px 16px' }}>Method</th>
                        <th style={{ padding: '12px 16px' }}>Host</th>
                        <th style={{ padding: '12px 16px' }}>URL / Path</th>
                        <th style={{ padding: '12px 12px' }}>Status</th>
                        <th style={{ padding: '12px 12px' }}>Content-Type</th>
                        <th style={{ padding: '12px 16px' }}>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {httpRequests.map((req) => {
                        const statusColor =
                          req.status_code && req.status_code < 300
                            ? '#34d399'
                            : req.status_code && req.status_code < 400
                            ? '#38bdf8'
                            : '#f87171';
                        return (
                          <tr
                            key={req.id}
                            onClick={() => setSelectedHttp(req)}
                            style={{
                              borderBottom: '1px solid rgba(31, 41, 55, 0.6)',
                              cursor: 'pointer',
                              transition: 'background-color 0.15s ease',
                            }}
                            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.03)')}
                            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                          >
                            <td style={{ padding: '12px 16px' }}>
                              <span style={{
                                fontSize: '11px',
                                fontFamily: 'monospace',
                                fontWeight: 700,
                                padding: '2px 6px',
                                borderRadius: '4px',
                                backgroundColor: req.method === 'GET' ? 'rgba(6, 182, 212, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                color: req.method === 'GET' ? '#22d3ee' : '#34d399',
                              }}>
                                {req.method}
                              </span>
                            </td>
                            <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#f8fafc', fontWeight: 600 }}>
                              {req.host || '-'}
                            </td>
                            <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: '#cbd5e1', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {req.path || req.url}
                            </td>
                            <td style={{ padding: '12px 12px' }}>
                              {req.status_code ? (
                                <span style={{
                                  fontSize: '11px',
                                  fontFamily: 'monospace',
                                  fontWeight: 600,
                                  color: statusColor,
                                }}>
                                  {req.status_code} {req.response_phrase}
                                </span>
                              ) : (
                                <span style={{ color: '#64748b', fontSize: '11px' }}>REQ</span>
                              )}
                            </td>
                            <td style={{ padding: '12px 12px', color: '#94a3b8', fontSize: '12px' }}>
                              {req.content_type || '-'}
                            </td>
                            <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px', fontFamily: 'monospace' }}>
                              {new Date(req.timestamp).toLocaleTimeString()}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )
            )}

            {/* 3. TLS TAB */}
            {activeTab === 'tls' && (
              tlsRecords.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }}>
                  <Lock size={36} style={{ color: '#475569', marginBottom: '10px' }} />
                  <p>No TLS handshake records found for the selected criteria.</p>
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #1f2937', backgroundColor: '#0e1422', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                        <th style={{ padding: '12px 16px' }}>Version</th>
                        <th style={{ padding: '12px 16px' }}>Server Name (SNI)</th>
                        <th style={{ padding: '12px 16px' }}>Negotiated Cipher Suite</th>
                        <th style={{ padding: '12px 12px' }}>ALPN Protocol</th>
                        <th style={{ padding: '12px 16px' }}>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tlsRecords.map((tls) => (
                        <tr
                          key={tls.id}
                          onClick={() => setSelectedTls(tls)}
                          style={{
                            borderBottom: '1px solid rgba(31, 41, 55, 0.6)',
                            cursor: 'pointer',
                            transition: 'background-color 0.15s ease',
                          }}
                          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.03)')}
                          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                        >
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{
                              fontSize: '11px',
                              fontFamily: 'monospace',
                              fontWeight: 700,
                              padding: '2px 6px',
                              borderRadius: '4px',
                              backgroundColor: tls.version.includes('1.3') ? 'rgba(139, 92, 246, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                              color: tls.version.includes('1.3') ? '#a78bfa' : '#60a5fa',
                            }}>
                              {tls.version}
                            </span>
                          </td>
                          <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontWeight: 600, color: '#f8fafc' }}>
                            {tls.sni || '<no SNI specified>'}
                          </td>
                          <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '12px', color: '#cbd5e1' }}>
                            {tls.cipher_suite || '-'}
                          </td>
                          <td style={{ padding: '12px 12px' }}>
                            {tls.alpn ? (
                              <span style={{
                                fontSize: '11px',
                                fontFamily: 'monospace',
                                color: '#34d399',
                                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                padding: '2px 6px',
                                borderRadius: '4px',
                              }}>
                                {tls.alpn}
                              </span>
                            ) : (
                              <span style={{ color: '#64748b' }}>-</span>
                            )}
                          </td>
                          <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px', fontFamily: 'monospace' }}>
                            {new Date(tls.timestamp).toLocaleTimeString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            )}

            {/* 4. CERTIFICATES TAB */}
            {activeTab === 'certificates' && (
              certificates.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }}>
                  <Award size={36} style={{ color: '#475569', marginBottom: '10px' }} />
                  <p>No X.509 certificates found for the selected criteria.</p>
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #1f2937', backgroundColor: '#0e1422', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                        <th style={{ padding: '12px 16px' }}>Subject (CN / Org)</th>
                        <th style={{ padding: '12px 16px' }}>Issuer</th>
                        <th style={{ padding: '12px 12px' }}>Status</th>
                        <th style={{ padding: '12px 12px' }}>Trust</th>
                        <th style={{ padding: '12px 16px' }}>SHA256 Fingerprint</th>
                        <th style={{ padding: '12px 16px' }}>Validity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {certificates.map((cert) => {
                        const isExpired = cert.valid_to ? new Date(cert.valid_to) < new Date() : false;
                        return (
                          <tr
                            key={cert.id}
                            onClick={() => setSelectedCert(cert)}
                            style={{
                              borderBottom: '1px solid rgba(31, 41, 55, 0.6)',
                              cursor: 'pointer',
                              backgroundColor: cert.is_self_signed ? 'rgba(239, 68, 68, 0.04)' : 'transparent',
                              transition: 'background-color 0.15s ease',
                            }}
                            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = cert.is_self_signed ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 255, 255, 0.03)')}
                            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = cert.is_self_signed ? 'rgba(239, 68, 68, 0.04)' : 'transparent')}
                          >
                            <td style={{ padding: '12px 16px' }}>
                              <div style={{ fontWeight: 600, color: '#f8fafc', fontFamily: 'monospace' }}>
                                {cert.subject_cn || '<No CN>'}
                              </div>
                              {cert.subject_org && (
                                <div style={{ fontSize: '11px', color: '#64748b' }}>{cert.subject_org}</div>
                              )}
                            </td>
                            <td style={{ padding: '12px 16px', fontSize: '12px', color: '#cbd5e1' }}>
                              {cert.issuer_cn || cert.issuer_org || 'Unknown Issuer'}
                            </td>
                            <td style={{ padding: '12px 12px' }}>
                              <span style={{
                                fontSize: '11px',
                                fontFamily: 'monospace',
                                fontWeight: 600,
                                padding: '2px 6px',
                                borderRadius: '4px',
                                backgroundColor: isExpired ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                color: isExpired ? '#f87171' : '#34d399',
                              }}>
                                {isExpired ? 'EXPIRED' : 'VALID'}
                              </span>
                            </td>
                            <td style={{ padding: '12px 12px' }}>
                              {cert.is_self_signed ? (
                                <span style={{
                                  fontSize: '11px',
                                  fontFamily: 'monospace',
                                  fontWeight: 700,
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  backgroundColor: 'rgba(239, 68, 68, 0.15)',
                                  color: '#ef4444',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                }}>
                                  <ShieldAlert size={12} /> SELF-SIGNED
                                </span>
                              ) : (
                                <span style={{
                                  fontSize: '11px',
                                  fontFamily: 'monospace',
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                  color: '#10b981',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                }}>
                                  <ShieldCheck size={12} /> CA VERIFIED
                                </span>
                              )}
                            </td>
                            <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontSize: '11px', color: '#94a3b8' }}>
                              {cert.fingerprint_sha256.slice(0, 16)}...
                            </td>
                            <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px' }}>
                              {cert.valid_to ? new Date(cert.valid_to).toLocaleDateString() : '-'}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )
            )}
          </div>
        )}
      </div>

      {/* ── MODALS FOR RECORD INSPECTION ── */}

      {/* DNS Detail Modal */}
      {selectedDns && (
        <div onClick={() => setSelectedDns(null)} style={modalBackdropStyle}>
          <div onClick={(e) => e.stopPropagation()} style={modalDialogStyle}>
            <div style={modalHeaderStyle}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Globe size={18} style={{ color: '#38bdf8' }} /> DNS Query Inspection
                </h3>
                <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px', fontFamily: 'monospace' }}>
                  ID: #{selectedDns.id}
                </div>
              </div>
              <button onClick={() => setSelectedDns(null)} style={closeBtnStyle}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '18px' }}>
              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Query Name</span>
                <div style={{ fontSize: '15px', color: '#38bdf8', fontFamily: 'monospace', fontWeight: 600 }}>
                  {selectedDns.query_name}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Record Type</span>
                  <div style={{ fontSize: '14px', color: '#f8fafc', fontWeight: 600 }}>{selectedDns.query_type}</div>
                </div>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Response Status</span>
                  <div style={{ fontSize: '14px', color: selectedDns.response_code === 'NOERROR' ? '#34d399' : '#f87171', fontWeight: 600 }}>
                    {selectedDns.response_code || 'QUERY'}
                  </div>
                </div>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>TTL</span>
                  <div style={{ fontSize: '14px', color: '#f8fafc' }}>
                    {selectedDns.ttl !== null ? `${selectedDns.ttl} seconds` : 'N/A'}
                  </div>
                </div>
              </div>

              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Answers / Resolved Targets</span>
                <div style={{ marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {parseAnswers(selectedDns.answers).length > 0 ? (
                    parseAnswers(selectedDns.answers).map((ans, idx) => (
                      <div key={idx} style={{ fontFamily: 'monospace', fontSize: '13px', color: '#34d399', backgroundColor: '#0e1422', padding: '6px 10px', borderRadius: '4px' }}>
                        {ans}
                      </div>
                    ))
                  ) : (
                    <div style={{ color: '#64748b', fontSize: '13px' }}>No answers received in packet.</div>
                  )}
                </div>
              </div>

              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Timestamp</span>
                <div style={{ fontSize: '13px', color: '#cbd5e1', fontFamily: 'monospace' }}>
                  {new Date(selectedDns.timestamp).toISOString()}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* HTTP Detail Modal */}
      {selectedHttp && (
        <div onClick={() => setSelectedHttp(null)} style={modalBackdropStyle}>
          <div onClick={(e) => e.stopPropagation()} style={modalDialogStyle}>
            <div style={modalHeaderStyle}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileCode size={18} style={{ color: '#34d399' }} /> HTTP Transaction Inspection
                </h3>
                <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px', fontFamily: 'monospace' }}>
                  ID: #{selectedHttp.id}
                </div>
              </div>
              <button onClick={() => setSelectedHttp(null)} style={closeBtnStyle}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '18px' }}>
              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Full Request URL</span>
                <div style={{ fontSize: '14px', color: '#34d399', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                  {selectedHttp.url}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 1fr', gap: '12px' }}>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Method</span>
                  <div style={{ fontSize: '15px', color: '#22d3ee', fontWeight: 700 }}>{selectedHttp.method}</div>
                </div>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Host Header</span>
                  <div style={{ fontSize: '14px', color: '#f8fafc', fontFamily: 'monospace' }}>{selectedHttp.host || '-'}</div>
                </div>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Response Status</span>
                  <div style={{ fontSize: '14px', color: selectedHttp.status_code && selectedHttp.status_code < 400 ? '#34d399' : '#f87171', fontWeight: 600 }}>
                    {selectedHttp.status_code ? `${selectedHttp.status_code} ${selectedHttp.response_phrase || ''}` : 'REQUEST'}
                  </div>
                </div>
              </div>

              {selectedHttp.user_agent && (
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>User-Agent Header</span>
                  <div style={{ fontSize: '13px', color: '#cbd5e1', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {selectedHttp.user_agent}
                  </div>
                </div>
              )}

              {selectedHttp.content_type && (
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Content-Type</span>
                  <div style={{ fontSize: '13px', color: '#cbd5e1', fontFamily: 'monospace' }}>
                    {selectedHttp.content_type}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TLS Detail Modal */}
      {selectedTls && (
        <div onClick={() => setSelectedTls(null)} style={modalBackdropStyle}>
          <div onClick={(e) => e.stopPropagation()} style={modalDialogStyle}>
            <div style={modalHeaderStyle}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Lock size={18} style={{ color: '#a78bfa' }} /> TLS Handshake Inspection
                </h3>
                <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px', fontFamily: 'monospace' }}>
                  ID: #{selectedTls.id}
                </div>
              </div>
              <button onClick={() => setSelectedTls(null)} style={closeBtnStyle}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '18px' }}>
              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Server Name Indication (SNI)</span>
                <div style={{ fontSize: '16px', color: '#a78bfa', fontFamily: 'monospace', fontWeight: 600 }}>
                  {selectedTls.sni || '<No SNI provided in ClientHello>'}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Protocol Version</span>
                  <div style={{ fontSize: '14px', color: '#f8fafc', fontWeight: 600 }}>{selectedTls.version}</div>
                </div>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>ALPN Application Layer</span>
                  <div style={{ fontSize: '14px', color: '#34d399', fontFamily: 'monospace' }}>{selectedTls.alpn || 'None'}</div>
                </div>
              </div>

              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Cipher Suite</span>
                <div style={{ fontSize: '13px', color: '#cbd5e1', fontFamily: 'monospace' }}>
                  {selectedTls.cipher_suite || 'Unspecified in record'}
                </div>
              </div>

              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Handshake Timestamp</span>
                <div style={{ fontSize: '13px', color: '#94a3b8', fontFamily: 'monospace' }}>
                  {new Date(selectedTls.timestamp).toISOString()}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Certificate Detail Modal */}
      {selectedCert && (
        <div onClick={() => setSelectedCert(null)} style={modalBackdropStyle}>
          <div onClick={(e) => e.stopPropagation()} style={modalDialogStyle}>
            <div style={modalHeaderStyle}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Award size={18} style={{ color: '#fbbf24' }} /> X.509 Certificate Inspection
                </h3>
                <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px', fontFamily: 'monospace' }}>
                  ID: #{selectedCert.id}
                </div>
              </div>
              <button onClick={() => setSelectedCert(null)} style={closeBtnStyle}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '18px' }}>
              {selectedCert.is_self_signed && (
                <div style={{
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  padding: '10px 14px',
                  borderRadius: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  color: '#ef4444',
                  fontSize: '13px',
                  fontWeight: 600,
                }}>
                  <ShieldAlert size={16} /> Warning: This certificate is self-signed and lacks a trusted third-party CA signature.
                </div>
              )}

              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Subject Common Name (CN)</span>
                <div style={{ fontSize: '15px', color: '#fbbf24', fontFamily: 'monospace', fontWeight: 600 }}>
                  {selectedCert.subject_cn || '<Empty>'}
                </div>
                {selectedCert.subject_org && (
                  <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>Org: {selectedCert.subject_org}</div>
                )}
              </div>

              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>Issuer (CA / Signer)</span>
                <div style={{ fontSize: '14px', color: '#f8fafc', fontFamily: 'monospace' }}>
                  {selectedCert.issuer_cn || selectedCert.issuer_org || 'Self-signed / Unknown'}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Valid From</span>
                  <div style={{ fontSize: '13px', color: '#cbd5e1' }}>
                    {selectedCert.valid_from ? new Date(selectedCert.valid_from).toUTCString() : 'N/A'}
                  </div>
                </div>
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Valid To</span>
                  <div style={{ fontSize: '13px', color: '#cbd5e1' }}>
                    {selectedCert.valid_to ? new Date(selectedCert.valid_to).toUTCString() : 'N/A'}
                  </div>
                </div>
              </div>

              <div style={fieldBlockStyle}>
                <span style={fieldLabelStyle}>SHA256 Fingerprint</span>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', marginTop: '4px' }}>
                  <span style={{ fontSize: '12px', color: '#38bdf8', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {selectedCert.fingerprint_sha256}
                  </span>
                  <button
                    onClick={() => handleCopy(selectedCert.fingerprint_sha256)}
                    style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
                  >
                    {copiedKey === selectedCert.fingerprint_sha256 ? <Check size={14} style={{ color: '#10b981' }} /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              {parseSans(selectedCert.san_list).length > 0 && (
                <div style={fieldBlockStyle}>
                  <span style={fieldLabelStyle}>Subject Alternative Names (SANs)</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                    {parseSans(selectedCert.san_list).map((san, idx) => (
                      <span key={idx} style={{
                        fontSize: '11px',
                        fontFamily: 'monospace',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        backgroundColor: '#0e1422',
                        color: '#94a3b8',
                        border: '1px solid #1f2937',
                      }}>
                        {san}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const modalBackdropStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  backgroundColor: 'rgba(0, 0, 0, 0.75)',
  backdropFilter: 'blur(4px)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 1000,
  padding: '20px',
};

const modalDialogStyle: React.CSSProperties = {
  backgroundColor: '#111827',
  border: '1px solid #1f2937',
  borderRadius: '16px',
  maxWidth: '680px',
  width: '100%',
  padding: '24px',
  boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
  maxHeight: '90vh',
  overflowY: 'auto',
};

const modalHeaderStyle: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'flex-start',
};

const closeBtnStyle: React.CSSProperties = {
  background: 'transparent',
  border: 'none',
  color: '#64748b',
  fontSize: '20px',
  cursor: 'pointer',
};

const fieldBlockStyle: React.CSSProperties = {
  backgroundColor: '#0b0f19',
  border: '1px solid #1f2937',
  borderRadius: '8px',
  padding: '10px 14px',
};

const fieldLabelStyle: React.CSSProperties = {
  fontSize: '11px',
  color: '#64748b',
  textTransform: 'uppercase',
  fontWeight: 600,
  display: 'block',
  marginBottom: '2px',
};
