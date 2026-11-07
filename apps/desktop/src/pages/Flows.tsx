import { useState, useEffect } from 'react';
import {
  Network,
  Search,
  ArrowRightLeft,
  Activity,
  Layers,
  Check,
  Copy,
  RefreshCw,
  Terminal,
} from 'lucide-react';
import { getFlows, getFlowDetail, type FlowRecord } from '../services/api';

export default function Flows() {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fetchFlowData = async () => {
    setLoading(true);
    try {
      const res = await getFlows({
        protocol: protocolFilter !== 'ALL' ? protocolFilter : undefined,
        search: searchTerm || undefined,
      });
      setFlows(res.flows);
    } catch (err) {
      console.error('Failed to load flows', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFlowData();
  }, [protocolFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchFlowData();
  };

  const handleRowClick = async (flow: FlowRecord) => {
    setSelectedFlow(flow);
    try {
      const detailed = await getFlowDetail(flow.id);
      setSelectedFlow(detailed);
    } catch {
      // Use existing flow object
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(text);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const totalBytes = flows.reduce((acc, f) => acc + f.bytes_total, 0);
  const totalPackets = flows.reduce((acc, f) => acc + f.packet_count, 0);

  const protocolList = ['ALL', 'TCP', 'UDP', 'TLS', 'HTTP', 'DNS', 'SMB'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Network Flow Intelligence
            </h1>
            <span style={{
              fontSize: '11px',
              fontFamily: 'monospace',
              padding: '2px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(139, 92, 246, 0.15)',
              color: '#a78bfa',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              fontWeight: 600,
            }}>
              PHASE 3 OPERATIONAL
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '640px' }}>
            Bi-directional session reconstruction from raw packet captures. Correlates 5-tuples, application protocols, volume ratios, and TCP state flags for rapid threat isolation.
          </p>
        </div>

        {/* Quick KPI badges */}
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Network size={16} style={{ color: '#a78bfa' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Active Flows</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>{flows.length}</div>
            </div>
          </div>

          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={16} style={{ color: 'var(--color-terminal)' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Packets</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>{totalPackets.toLocaleString()}</div>
            </div>
          </div>

          <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={16} style={{ color: 'var(--color-cyan)' }} />
            <div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Traffic Volume</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc' }}>{(totalBytes / 1024).toFixed(1)} KB</div>
            </div>
          </div>
        </div>
      </div>

      {/* Control Bar: Protocol Filters & Search */}
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
        {/* Protocol Tabs */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {protocolList.map((proto) => (
            <button
              key={proto}
              onClick={() => setProtocolFilter(proto)}
              style={{
                backgroundColor: protocolFilter === proto ? '#8b5cf6' : '#1e293b',
                color: protocolFilter === proto ? '#ffffff' : '#94a3b8',
                border: `1px solid ${protocolFilter === proto ? '#8b5cf6' : '#334155'}`,
                borderRadius: '6px',
                padding: '5px 12px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              {proto}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <form onSubmit={handleSearch} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            backgroundColor: '#0b0f19',
            border: '1px solid #334155',
            borderRadius: '8px',
            padding: '6px 12px',
            gap: '8px',
          }}>
            <Search size={15} style={{ color: '#64748b' }} />
            <input
              type="text"
              placeholder="Search IP, Port, or Service..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#f8fafc',
                fontSize: '13px',
                outline: 'none',
                width: '210px',
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
              setProtocolFilter('ALL');
              fetchFlowData();
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

      {/* Main Flow Table */}
      <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
            Dissecting packet flows...
          </div>
        ) : flows.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }}>
            <Network size={36} style={{ color: '#475569', marginBottom: '10px' }} />
            <p>No network flows match the selected criteria.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1f2937', backgroundColor: '#0e1422', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                  <th style={{ padding: '12px 16px' }}>Source Endpoint</th>
                  <th style={{ padding: '12px 8px', textAlign: 'center' }}>Dir</th>
                  <th style={{ padding: '12px 16px' }}>Destination Endpoint</th>
                  <th style={{ padding: '12px 12px' }}>Protocol</th>
                  <th style={{ padding: '12px 12px' }}>Packets</th>
                  <th style={{ padding: '12px 12px' }}>Volume</th>
                  <th style={{ padding: '12px 12px' }}>TCP Flags</th>
                  <th style={{ padding: '12px 16px' }}>Forensic Summary</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((flow) => {
                  const isSuspicious = flow.summary.toLowerCase().includes('c2') || flow.summary.toLowerCase().includes('beacon');
                  return (
                    <tr
                      key={flow.id}
                      onClick={() => handleRowClick(flow)}
                      style={{
                        borderBottom: '1px solid rgba(31, 41, 55, 0.6)',
                        cursor: 'pointer',
                        backgroundColor: isSuspicious ? 'rgba(239, 68, 68, 0.05)' : 'transparent',
                        transition: 'background-color 0.15s ease',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = isSuspicious ? 'rgba(239, 68, 68, 0.1)' : 'rgba(255, 255, 255, 0.03)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = isSuspicious ? 'rgba(239, 68, 68, 0.05)' : 'transparent')}
                    >
                      {/* Src */}
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace' }}>
                        <span style={{ color: '#f8fafc', fontWeight: 600 }}>{flow.src_ip}</span>
                        <span style={{ color: '#64748b' }}>:{flow.src_port}</span>
                      </td>

                      {/* Arrow */}
                      <td style={{ padding: '12px 8px', textAlign: 'center', color: '#64748b' }}>
                        <ArrowRightLeft size={13} />
                      </td>

                      {/* Dst */}
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace' }}>
                        <span style={{ color: '#f8fafc', fontWeight: 600 }}>{flow.dst_ip}</span>
                        <span style={{ color: '#64748b' }}>:{flow.dst_port}</span>
                      </td>

                      {/* Protocol / App */}
                      <td style={{ padding: '12px 12px' }}>
                        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                          <span style={{
                            fontSize: '11px',
                            fontFamily: 'monospace',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            backgroundColor: flow.protocol === 'TCP' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(6, 182, 212, 0.15)',
                            color: flow.protocol === 'TCP' ? '#34d399' : '#22d3ee',
                          }}>
                            {flow.protocol}
                          </span>
                          {flow.application && flow.application !== flow.protocol && (
                            <span style={{
                              fontSize: '11px',
                              fontFamily: 'monospace',
                              fontWeight: 600,
                              padding: '2px 6px',
                              borderRadius: '4px',
                              backgroundColor: 'rgba(139, 92, 246, 0.15)',
                              color: '#a78bfa',
                            }}>
                              {flow.application}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Packets */}
                      <td style={{ padding: '12px 12px', color: '#cbd5e1' }}>
                        {flow.packet_count}
                      </td>

                      {/* Volume */}
                      <td style={{ padding: '12px 12px', color: '#94a3b8' }}>
                        {(flow.bytes_total / 1024).toFixed(1)} KB
                      </td>

                      {/* Flags */}
                      <td style={{ padding: '12px 12px' }}>
                        <span style={{
                          fontSize: '11px',
                          fontFamily: 'monospace',
                          color: flow.tcp_flags.includes('RST') ? '#ef4444' : '#94a3b8',
                        }}>
                          {flow.tcp_flags}
                        </span>
                      </td>

                      {/* Summary */}
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{
                          color: isSuspicious ? '#f87171' : '#cbd5e1',
                          fontWeight: isSuspicious ? 600 : 400,
                          fontSize: '12px',
                          maxWidth: '320px',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}>
                          {flow.summary}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Flow Session Detail Drawer / Modal */}
      {selectedFlow && (
        <div
          onClick={() => setSelectedFlow(null)}
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
              maxWidth: '720px',
              width: '100%',
              padding: '24px',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
              maxHeight: '90vh',
              overflowY: 'auto',
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Network size={20} style={{ color: '#8b5cf6' }} />
                  <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                    Network Flow Inspection
                  </h3>
                </div>
                <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px', fontFamily: 'monospace' }}>
                  ID: #{selectedFlow.id} • {selectedFlow.flow_key}
                </div>
              </div>

              <button
                onClick={() => setSelectedFlow(null)}
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

            {/* Endpoints Matrix */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr auto 1fr',
              alignItems: 'center',
              backgroundColor: '#0b0f19',
              border: '1px solid #1f2937',
              borderRadius: '10px',
              padding: '16px',
              marginTop: '18px',
              gap: '12px',
            }}>
              <div>
                <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase' }}>Client Initiator</span>
                <div style={{ fontSize: '16px', fontWeight: 700, color: '#38bdf8', fontFamily: 'monospace', marginTop: '2px' }}>
                  {selectedFlow.src_ip}
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>Port: {selectedFlow.src_port}</div>
              </div>

              <div style={{ textAlign: 'center', color: '#8b5cf6' }}>
                <ArrowRightLeft size={24} />
                <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', marginTop: '2px' }}>
                  {selectedFlow.protocol}
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase' }}>Server Responder</span>
                <div style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc', fontFamily: 'monospace', marginTop: '2px' }}>
                  {selectedFlow.dst_ip}
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>Port: {selectedFlow.dst_port}</div>
              </div>
            </div>

            {/* Metrics Breakdown */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginTop: '14px' }}>
              <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>Total Packets</div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', marginTop: '2px' }}>
                  {selectedFlow.packet_count}
                </div>
              </div>

              <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>Total Volume</div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', marginTop: '2px' }}>
                  {(selectedFlow.bytes_total / 1024).toFixed(1)} KB
                </div>
              </div>

              <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>Client Sent</div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: '#38bdf8', marginTop: '2px' }}>
                  {(selectedFlow.bytes_forward / 1024).toFixed(1)} KB
                </div>
              </div>

              <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '11px', color: '#64748b' }}>Server Sent</div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: '#a78bfa', marginTop: '2px' }}>
                  {(selectedFlow.bytes_reverse / 1024).toFixed(1)} KB
                </div>
              </div>
            </div>

            {/* Summary Banner */}
            <div style={{
              backgroundColor: 'rgba(139, 92, 246, 0.08)',
              border: '1px solid rgba(139, 92, 246, 0.25)',
              borderRadius: '8px',
              padding: '12px',
              marginTop: '14px',
              fontSize: '13px',
              color: '#cbd5e1',
            }}>
              <span style={{ fontWeight: 600, color: '#a78bfa' }}>Forensic Observation: </span>
              {selectedFlow.summary}
            </div>

            {/* Hex Dump Payload Preview */}
            <div style={{ marginTop: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Terminal size={14} style={{ color: 'var(--color-terminal)' }} />
                  <span style={{ fontSize: '12px', fontWeight: 600, color: '#cbd5e1' }}>Payload Packet Inspection (Hex / ASCII)</span>
                </div>
                <button
                  onClick={() => handleCopy(selectedFlow.payload_hex_preview || '')}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: copiedKey === selectedFlow.payload_hex_preview ? '#10b981' : '#64748b',
                    fontSize: '11px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    cursor: 'pointer',
                  }}
                >
                  {copiedKey === selectedFlow.payload_hex_preview ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedKey === selectedFlow.payload_hex_preview ? 'Copied' : 'Copy Hex'}</span>
                </button>
              </div>

              <pre style={{
                backgroundColor: '#05070d',
                border: '1px solid #1f2937',
                borderRadius: '8px',
                padding: '12px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: '#34d399',
                overflowX: 'auto',
                margin: 0,
                lineHeight: '1.5',
              }}>
                {selectedFlow.payload_hex_preview ||
`0000   45 00 00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 01 69   E..<.@.@.......i
0010   68 f4 2a 01 d3 c2 01 bb 3a 45 12 00 00 00 00 00   h.*.....:E......
0020   a0 02 72 10 9f e2 00 00 02 04 05 b4 04 02 08 0a   ..r.............
0030   0e 43 f1 2a 00 00 00 00 01 03 03 07               .C.*........    `}
              </pre>
            </div>

            {/* Close Button */}
            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedFlow(null)}
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
                Close Session
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
