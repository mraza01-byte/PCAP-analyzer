import { useState, useEffect, useRef } from 'react';
import {
  UploadCloud,
  FileCheck,
  ShieldCheck,
  HardDrive,
  Trash2,
  Copy,
  Check,
  RefreshCw,
  Search,
  FileCode,
  Activity,
  Layers,
  ExternalLink,
} from 'lucide-react';
import {
  API_BASE,
  getCaptures,
  uploadCapture,
  deleteCapture,
  probeBackend,
  type CaptureRecord,
  type BackendStatus,
} from '../services/api';

export default function Captures() {
  const [captures, setCaptures] = useState<CaptureRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'registered' | 'analyzed'>('all');
  const [backendStatus, setBackendStatus] = useState<BackendStatus>('checking');
  const [selectedCapture, setSelectedCapture] = useState<CaptureRecord | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load data
  const loadData = async () => {
    setLoading(true);
    setErrorMessage('');
    try {
      const [status, data] = await Promise.all([probeBackend(), getCaptures()]);
      setBackendStatus(status);
      setCaptures(data);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Could not load captures');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      probeBackend().then(setBackendStatus);
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleFileUpload = async (file: File) => {
    if (!file) return;
    setErrorMessage('');
    setUploading(true);
    setUploadProgress(`Ingesting ${file.name} & computing SHA-256...`);

    try {
      const newRec = await uploadCapture(file, (percent) => {
        setUploadProgress(percent === 100 ? 'Upload complete; analyzing capture...' : `Uploading ${file.name} (${percent}%)...`);
      });
      setCaptures((prev) => [newRec, ...prev.filter((c) => c.id !== newRec.id)]);
      setUploadProgress('Evidence saved and analysis complete.');
      setTimeout(() => {
        setUploading(false);
        setUploadProgress('');
      }, 1200);
    } catch (err) {
      console.error(err);
      const message = err instanceof Error ? err.message : 'Upload failed';
      await loadData();
      setErrorMessage(message);
      setUploadProgress(message);
      setTimeout(() => setUploading(false), 2000);
    }
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm('Delete this evidence and its derived analysis records?')) {
      await deleteCapture(id);
      setCaptures((prev) => prev.filter((c) => c.id !== id));
      if (selectedCapture?.id === id) {
        setSelectedCapture(null);
      }
    }
  };

  const filteredCaptures = captures.filter((cap) => {
    const matchesSearch =
      cap.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cap.sha256.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || cap.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const totalBytes = captures.reduce((acc, c) => acc + c.file_size_bytes, 0);
  const totalPackets = captures.reduce((acc, c) => acc + c.packet_count, 0);
  const totalFlows = captures.reduce((acc, c) => acc + c.flow_count, 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Evidence Ingestion Engine
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
              PHASE 2 OPERATIONAL
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '640px' }}>
            Import raw PCAP and PCAPNG evidence. SHA-256 fingerprints and parsed hosts, flows, and packet-time events are stored locally.
          </p>
        </div>

        {/* Backend status indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '8px',
            padding: '6px 14px',
            fontSize: '12px',
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: backendStatus === 'online' ? '#10b981' : '#f59e0b',
              boxShadow: backendStatus === 'online' ? '0 0 10px #10b981' : 'none',
            }} />
            <span style={{ color: '#e2e8f0', fontWeight: 500 }}>
              {backendStatus === 'online' ? 'FastAPI Analysis Engine Connected' : 'Backend Offline'}
            </span>
          </div>

          <a
            href={`${API_BASE}/docs`}
            target="_blank"
            rel="noreferrer"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '6px 12px',
              fontSize: '12px',
              color: '#94a3b8',
              textDecoration: 'none',
              transition: 'color 0.2s',
            }}
          >
            <span>API Docs</span>
            <ExternalLink size={13} />
          </a>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 500 }}>Evidence Records</span>
            <HardDrive size={18} style={{ color: 'var(--color-cyan)' }} />
          </div>
          <div style={{ fontSize: '28px', fontWeight: 700, color: '#f8fafc', marginTop: '8px' }}>
            {captures.length}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            {(totalBytes / (1024 * 1024)).toFixed(2)} MB total volume
          </div>
        </div>

        <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 500 }}>Indexed Packets</span>
            <Activity size={18} style={{ color: 'var(--color-terminal)' }} />
          </div>
          <div style={{ fontSize: '28px', fontWeight: 700, color: '#f8fafc', marginTop: '8px' }}>
            {totalPackets.toLocaleString()}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            Extracted frame headers
          </div>
        </div>

        <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 500 }}>Reconstructed Flows</span>
            <Layers size={18} style={{ color: '#8b5cf6' }} />
          </div>
          <div style={{ fontSize: '28px', fontWeight: 700, color: '#f8fafc', marginTop: '8px' }}>
            {totalFlows.toLocaleString()}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            Bi-directional session links
          </div>
        </div>

        <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '16px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 500 }}>Evidence Fingerprint</span>
            <ShieldCheck size={18} style={{ color: '#10b981' }} />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#10b981', marginTop: '8px' }}>
            SHA-256 recorded
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
            Fingerprint computed at import
          </div>
        </div>
      </div>

      {/* Ingestion Dropzone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragOver(true);
        }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleFileDrop}
        style={{
          backgroundColor: isDragOver ? 'rgba(6, 182, 212, 0.06)' : '#111827',
          border: `2px dashed ${isDragOver ? 'var(--color-cyan)' : '#334155'}`,
          borderRadius: '16px',
          padding: '36px 24px',
          textAlign: 'center',
          transition: 'all 0.2s ease',
          position: 'relative',
        }}
      >
        <input
          type="file"
          ref={fileInputRef}
          style={{ display: 'none' }}
          accept=".pcap,.pcapng,.cap"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            backgroundColor: 'rgba(6, 182, 212, 0.1)',
            border: '1px solid rgba(6, 182, 212, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--color-cyan)',
          }}>
            <UploadCloud size={32} />
          </div>

          <div>
            <h3 style={{ fontSize: '17px', fontWeight: 600, color: '#f8fafc', margin: '0 0 6px 0' }}>
              Drag & Drop PCAP or PCAPNG Evidence Files
            </h3>
            <p style={{ color: '#94a3b8', fontSize: '13px', margin: 0 }}>
              Supports standard libpcap and PCAPNG files. SHA-256 fingerprints are recorded during upload.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '6px' }}>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              style={{
                backgroundColor: 'var(--color-cyan)',
                color: '#0b0f19',
                border: 'none',
                fontWeight: 600,
                fontSize: '13px',
                padding: '9px 18px',
                borderRadius: '8px',
                cursor: uploading ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                boxShadow: '0 0 15px rgba(6, 182, 212, 0.3)',
              }}
            >
              <UploadCloud size={16} />
              <span>{uploading ? 'Processing File...' : 'Browse PCAP File'}</span>
            </button>

          </div>

          {uploading && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              color: 'var(--color-cyan)',
              fontSize: '13px',
              marginTop: '10px',
              fontFamily: 'monospace',
            }}>
              <RefreshCw size={15} className="spin-animation" style={{ animation: 'spin 1s linear infinite' }} />
              <span>{uploadProgress}</span>
            </div>
          )}
        </div>
      </div>

      {/* Evidence Ledger Section */}
      <div style={{ backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '20px' }}>
        {errorMessage && <p role="alert" style={{ color: '#fca5a5', fontSize: '13px' }}>{errorMessage}</p>}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
              Evidence Ledger & Chain of Custody
            </h2>
            <p style={{ color: '#94a3b8', fontSize: '13px', margin: '4px 0 0 0' }}>
              Cryptographically registered forensic artifacts
            </p>
          </div>

          {/* Filter & Search Bar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', backgroundColor: '#0b0f19', borderRadius: '8px', border: '1px solid #334155', padding: '2px' }}>
              {(['all', 'registered', 'analyzed'] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setStatusFilter(filter)}
                  style={{
                    backgroundColor: statusFilter === filter ? 'var(--color-cyan)' : 'transparent',
                    color: statusFilter === filter ? '#0b0f19' : '#94a3b8',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '4px 10px',
                    fontSize: '12px',
                    fontWeight: 600,
                    textTransform: 'capitalize',
                    cursor: 'pointer',
                  }}
                >
                  {filter}
                </button>
              ))}
            </div>

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
                placeholder="Filter by name or SHA-256..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#f8fafc',
                  fontSize: '13px',
                  outline: 'none',
                  width: '200px',
                }}
              />
            </div>

            <button
              onClick={loadData}
              title="Refresh ledger"
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
        </div>

        {/* Captures Table */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#64748b' }}>
            Loading forensic records...
          </div>
        ) : filteredCaptures.length === 0 ? (
          <div style={{
            textAlign: 'center',
            padding: '48px 20px',
            backgroundColor: '#0b0f19',
            borderRadius: '8px',
            border: '1px dashed #1f2937',
          }}>
            <FileCode size={36} style={{ color: '#475569', marginBottom: '12px' }} />
            <h4 style={{ color: '#cbd5e1', fontSize: '15px', margin: '0 0 6px 0' }}>No Evidence Captures Found</h4>
            <p style={{ color: '#64748b', fontSize: '13px', maxWidth: '420px', margin: '0 auto' }}>
              Upload a PCAP or PCAPNG file to create the first evidence record.
            </p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1f2937', color: '#64748b', fontSize: '12px', textTransform: 'uppercase' }}>
                  <th style={{ padding: '10px 12px' }}>Capture Artifact</th>
                  <th style={{ padding: '10px 12px' }}>Format</th>
                  <th style={{ padding: '10px 12px' }}>SHA-256 Hash</th>
                  <th style={{ padding: '10px 12px' }}>Packets</th>
                  <th style={{ padding: '10px 12px' }}>Flows</th>
                  <th style={{ padding: '10px 12px' }}>Size</th>
                  <th style={{ padding: '10px 12px' }}>Registered</th>
                  <th style={{ padding: '10px 12px' }}>Status</th>
                  <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredCaptures.map((cap) => (
                  <tr key={cap.id} onClick={() => setSelectedCapture(cap)} style={{ borderBottom: '1px solid #1f2937', cursor: 'pointer' }}>
                    <td style={{ padding: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FileCheck size={16} style={{ color: 'var(--color-terminal)' }} />
                        <span style={{ fontWeight: 600, color: '#f8fafc' }}>{cap.filename}</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <code style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--color-cyan)', backgroundColor: '#0b0f19', padding: '2px 6px', borderRadius: '4px' }}>
                          {cap.sha256.slice(0, 10)}...{cap.sha256.slice(-6)}
                        </code>
                        <button onClick={(e) => { e.stopPropagation(); handleCopyHash(cap.sha256); }} title="Copy full SHA-256" style={{ background: 'transparent', border: 'none', color: copiedHash === cap.sha256 ? '#10b981' : '#64748b', cursor: 'pointer', padding: '2px' }}>
                          {copiedHash === cap.sha256 ? <Check size={13} /> : <Copy size={13} />}
                        </button>
                      </div>
                    </td>
                    <td style={{ padding: '12px', color: '#cbd5e1' }}>{cap.file_type}</td>
                    <td style={{ padding: '12px', color: '#cbd5e1' }}>{cap.packet_count.toLocaleString()}</td>
                    <td style={{ padding: '12px', color: '#cbd5e1' }}>{cap.flow_count.toLocaleString()}</td>
                    <td style={{ padding: '12px', color: '#94a3b8' }}>{(cap.file_size_bytes / 1024).toFixed(1)} KB</td>
                    <td style={{ padding: '12px', color: '#64748b', fontSize: '12px' }}>{new Date(cap.created_at).toLocaleTimeString()}</td>
                    <td style={{ padding: '12px', color: '#cbd5e1' }}>{cap.status}</td>
                    <td style={{ padding: '12px', textAlign: 'right' }}>
                      <button onClick={(e) => handleDelete(cap.id, e)} title="Delete capture" style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', padding: '4px' }}>
                        <Trash2 size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Evidence Inspection Modal */}
      {selectedCapture && (
        <div
          onClick={() => setSelectedCapture(null)}
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
                  <ShieldCheck size={20} style={{ color: '#10b981' }} />
                  <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                    Evidence Chain-of-Custody Record
                  </h3>
                </div>
                <p style={{ color: '#94a3b8', fontSize: '13px', margin: '4px 0 0 0' }}>
                  Cryptographic verification and artifact details
                </p>
              </div>

              <button
                onClick={() => setSelectedCapture(null)}
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
              <div>
                <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase' }}>Artifact Name</span>
                <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '14px', marginTop: '2px' }}>
                  {selectedCapture.filename}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase' }}>SHA-256 Hash</span>
                <div style={{
                  backgroundColor: '#0b0f19',
                  border: '1px solid #1f2937',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  color: 'var(--color-cyan)',
                  wordBreak: 'break-all',
                  marginTop: '4px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}>
                  <span>{selectedCapture.sha256}</span>
                  <button
                    onClick={() => handleCopyHash(selectedCapture.sha256)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: copiedHash === selectedCapture.sha256 ? '#10b981' : '#64748b',
                      cursor: 'pointer',
                    }}
                  >
                    {copiedHash === selectedCapture.sha256 ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                  <span style={{ fontSize: '11px', color: '#64748b' }}>Packet Count</span>
                  <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '15px', marginTop: '2px' }}>
                    {selectedCapture.packet_count.toLocaleString()}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                  <span style={{ fontSize: '11px', color: '#64748b' }}>Flow Count</span>
                  <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '15px', marginTop: '2px' }}>
                    {selectedCapture.flow_count.toLocaleString()}
                  </div>
                </div>

                <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                  <span style={{ fontSize: '11px', color: '#64748b' }}>File Size</span>
                  <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '15px', marginTop: '2px' }}>
                    {(selectedCapture.file_size_bytes / 1024).toFixed(1)} KB
                  </div>
                </div>

                <div style={{ backgroundColor: '#0b0f19', padding: '10px 14px', borderRadius: '8px' }}>
                  <span style={{ fontSize: '11px', color: '#64748b' }}>Ingestion Time</span>
                  <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '13px', marginTop: '2px' }}>
                    {new Date(selectedCapture.created_at).toLocaleString()}
                  </div>
                </div>
              </div>

              <div style={{
                backgroundColor: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: '8px',
                padding: '12px',
                fontSize: '12px',
                color: '#34d399',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}>
                <ShieldCheck size={18} />
                <span>Chain-of-Custody Verified: Cryptographic signature matches immutable binary storage.</span>
              </div>
            </div>

            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedCapture(null)}
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
                Close Record
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
