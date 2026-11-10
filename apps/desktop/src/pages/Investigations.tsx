import { useState, useEffect } from 'react';
import {
  Plus,
  FolderOpen,
  User,
  Clock,
  Trash2,
  Save,
  Check,
  Search,
  RefreshCw,
} from 'lucide-react';
import {
  getCaptures,
  getInvestigations,
  createInvestigation,
  updateInvestigation,
  deleteInvestigation,
  type InvestigationCaseRecord,
  type CaptureRecord,
} from '../services/api';

export default function Investigations() {
  const [cases, setCases] = useState<InvestigationCaseRecord[]>([]);
  const [captures, setCaptures] = useState<CaptureRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');
  const [selectedCase, setSelectedCase] = useState<InvestigationCaseRecord | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Form states
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState('high');
  const [newAnalyst, setNewAnalyst] = useState('PCAP-MAN (Lead Forensic Specialist)');
  const [newDesc, setNewDesc] = useState('');
  const [newIoc, setNewIoc] = useState('');
  const [newCaptureId, setNewCaptureId] = useState('');

  // Editing state
  const [editFindings, setEditFindings] = useState('');
  const [editStatus, setEditStatus] = useState<InvestigationCaseRecord['status']>('active');

  const fetchCases = async () => {
    setLoading(true);
    setErrorMessage('');
    try {
      const [data, captureData] = await Promise.all([getInvestigations(), getCaptures()]);
      setCases(data);
      setCaptures(captureData);
      if (selectedCase) {
        const refreshed = data.find((c) => c.id === selectedCase.id);
        if (refreshed) {
          setSelectedCase(refreshed);
          setEditFindings(refreshed.findings || '');
          setEditStatus(refreshed.status);
        }
      }
    } catch (err) {
      console.error(err);
      setErrorMessage(err instanceof Error ? err.message : 'Could not load investigations');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleOpenCase = (c: InvestigationCaseRecord) => {
    setSelectedCase(c);
    setEditFindings(c.findings || '');
    setEditStatus(c.status);
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle) return;

    try {
      const created = await createInvestigation({
        title: newTitle,
        severity: newSeverity,
        lead_analyst: newAnalyst,
        description: newDesc,
        ioc_list: newIoc,
        linked_capture_ids: newCaptureId ? [newCaptureId] : [],
      });
      setCases((prev) => [created, ...prev]);
      setIsCreateOpen(false);
      setNewTitle('');
      setNewDesc('');
      setNewIoc('');
      setNewCaptureId('');
      handleOpenCase(created);
    } catch (err) {
      console.error('Failed to create case', err);
      setErrorMessage(err instanceof Error ? err.message : 'Could not create investigation');
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedCase) return;
    try {
      const updated = await updateInvestigation(selectedCase.id, {
        findings: editFindings,
        status: editStatus,
      });
      setSelectedCase(updated);
      setCases((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 2000);
    } catch (err) {
      console.error('Failed to update case', err);
      setErrorMessage(err instanceof Error ? err.message : 'Could not update investigation');
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm('Permanently close and delete this forensic case?')) {
      try {
        await deleteInvestigation(id);
        setCases((prev) => prev.filter((c) => c.id !== id));
        if (selectedCase?.id === id) setSelectedCase(null);
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Could not delete investigation');
      }
    }
  };

  const filteredCases = cases.filter(
    (c) =>
      c.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.case_number.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (c.description && c.description.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Forensic Case Workspace
            </h1>
            <span style={{
              fontSize: '11px',
              fontFamily: 'monospace',
              padding: '2px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(245, 158, 11, 0.15)',
              color: '#fbbf24',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              fontWeight: 600,
            }}>
              PHASE 4 OPERATIONAL
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '640px' }}>
            Malcolm & Elastic Security inspired incident case manager. Link capture evidence, record investigative hypotheses, correlate indicators of compromise (IOCs), and produce audit-ready findings.
          </p>
        </div>

        {/* Create Case Button */}
        <button
          onClick={() => setIsCreateOpen(true)}
          style={{
            backgroundColor: '#f59e0b',
            color: '#0b0f19',
            border: 'none',
            borderRadius: '8px',
            padding: '9px 18px',
            fontSize: '13px',
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: '0 0 15px rgba(245, 158, 11, 0.3)',
          }}
        >
          <Plus size={16} />
          <span>New Forensic Case</span>
        </button>
      </div>
      {errorMessage && <div role="alert" style={{ color: '#fca5a5', fontSize: '13px' }}>{errorMessage}</div>}

      {/* Main Workspace Layout (Left: Cases List, Right: Active Case Dossier) */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedCase ? '1fr 1.3fr' : '1fr', gap: '20px', alignItems: 'flex-start' }}>
        {/* Cases List Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Search Bar */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '10px',
            padding: '8px 14px',
            gap: '10px',
          }}>
            <Search size={15} style={{ color: '#64748b' }} />
            <input
              type="text"
              placeholder="Search active cases or IOCs..."
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
            <button
              onClick={fetchCases}
              style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer' }}
            >
              <RefreshCw size={14} />
            </button>
          </div>

          {/* Cases Cards */}
          {errorMessage ? (
            <div role="alert" style={{ textAlign: 'center', padding: '40px', color: '#fca5a5' }}>{errorMessage}</div>
          ) : loading ? (
            <div style={{ textAlign: 'center', padding: '40px', color: '#64748b' }}>
              Loading investigation files...
            </div>
          ) : filteredCases.length === 0 ? (
            <div style={{
              textAlign: 'center',
              padding: '48px 20px',
              backgroundColor: '#111827',
              borderRadius: '12px',
              border: '1px dashed #1f2937',
            }}>
              <FolderOpen size={36} style={{ color: '#475569', marginBottom: '10px' }} />
              <h4 style={{ color: '#cbd5e1', fontSize: '15px', margin: '0 0 6px 0' }}>No Active Cases Found</h4>
              <p style={{ color: '#64748b', fontSize: '13px', margin: '0 auto 16px auto', maxWidth: '300px' }}>
                Open an investigation case to correlate evidence from your network packet captures.
              </p>
              <button
                onClick={() => setIsCreateOpen(true)}
                style={{
                  backgroundColor: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  color: '#fbbf24',
                  borderRadius: '8px',
                  padding: '7px 14px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Create First Case
              </button>
            </div>
          ) : (
            filteredCases.map((c) => {
              const isSelected = selectedCase?.id === c.id;
              const isCritical = c.severity === 'critical';

              return (
                <div
                  key={c.id}
                  onClick={() => handleOpenCase(c)}
                  style={{
                    backgroundColor: '#111827',
                    border: `1px solid ${isSelected ? '#f59e0b' : '#1f2937'}`,
                    borderRadius: '12px',
                    padding: '16px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    boxShadow: isSelected ? '0 0 20px rgba(245, 158, 11, 0.15)' : 'none',
                  }}
                  onMouseEnter={(e) => {
                    if (!isSelected) e.currentTarget.style.borderColor = '#374151';
                  }}
                  onMouseLeave={(e) => {
                    if (!isSelected) e.currentTarget.style.borderColor = '#1f2937';
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{
                        fontSize: '11px',
                        fontFamily: 'monospace',
                        fontWeight: 700,
                        color: '#f59e0b',
                        backgroundColor: '#0b0f19',
                        padding: '2px 6px',
                        borderRadius: '4px',
                      }}>
                        {c.case_number}
                      </span>
                      <span style={{
                        fontSize: '10px',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        backgroundColor: isCritical ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                        color: isCritical ? '#f87171' : '#fbbf24',
                      }}>
                        {c.severity}
                      </span>
                    </div>

                    <span style={{
                      fontSize: '11px',
                      textTransform: 'capitalize',
                      color: c.status === 'active' ? '#10b981' : '#94a3b8',
                      fontWeight: 600,
                    }}>
                      • {c.status.replace('_', ' ')}
                    </span>
                  </div>

                  <h3 style={{ fontSize: '15px', fontWeight: 600, color: '#f8fafc', margin: '10px 0 6px 0' }}>
                    {c.title}
                  </h3>

                  <p style={{
                    color: '#94a3b8',
                    fontSize: '12px',
                    margin: 0,
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                    lineHeight: '1.4',
                  }}>
                    {c.description}
                  </p>

                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginTop: '12px',
                    paddingTop: '10px',
                    borderTop: '1px solid #1f2937',
                    fontSize: '11px',
                    color: '#64748b',
                  }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <User size={12} />
                      {c.lead_analyst}
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Clock size={12} />
                      {new Date(c.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Case Dossier Editor (Right Column) */}
        {selectedCase && (
          <div style={{
            backgroundColor: '#111827',
            border: '1px solid #1f2937',
            borderRadius: '16px',
            padding: '24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '18px',
          }}>
            {/* Dossier Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    fontWeight: 700,
                    backgroundColor: 'rgba(245, 158, 11, 0.15)',
                    color: '#fbbf24',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    border: '1px solid rgba(245, 158, 11, 0.3)',
                  }}>
                    {selectedCase.case_number}
                  </span>
                  <select
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value as any)}
                    style={{
                      backgroundColor: '#0b0f19',
                      border: '1px solid #334155',
                      color: '#cbd5e1',
                      borderRadius: '6px',
                      padding: '4px 8px',
                      fontSize: '12px',
                      fontWeight: 600,
                    }}
                  >
                    <option value="active">Status: Active</option>
                    <option value="under_review">Status: Under Review</option>
                    <option value="escalated">Status: Escalated</option>
                    <option value="closed">Status: Closed</option>
                  </select>
                </div>

                <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc', margin: '8px 0 2px 0' }}>
                  {selectedCase.title}
                </h2>
                <div style={{ fontSize: '12px', color: '#64748b' }}>
                  Investigator: <span style={{ color: '#cbd5e1' }}>{selectedCase.lead_analyst}</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={handleSaveNotes}
                  style={{
                    backgroundColor: savedSuccess ? '#10b981' : '#f59e0b',
                    color: '#0b0f19',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '7px 14px',
                    fontSize: '12px',
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    transition: 'background-color 0.2s',
                  }}
                >
                  {savedSuccess ? <Check size={14} /> : <Save size={14} />}
                  <span>{savedSuccess ? 'Saved' : 'Save Dossier'}</span>
                </button>

                <button
                  onClick={() => handleDelete(selectedCase.id)}
                  title="Delete Case"
                  style={{
                    backgroundColor: '#1e293b',
                    color: '#ef4444',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '7px 10px',
                    cursor: 'pointer',
                  }}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            {/* Incident Summary */}
            <div style={{ backgroundColor: '#0b0f19', padding: '14px', borderRadius: '10px', border: '1px solid #1f2937' }}>
              <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>
                Incident Hypothesis & Initial Telemetry
              </div>
              <p style={{ color: '#cbd5e1', fontSize: '13px', margin: '6px 0 0 0', lineHeight: '1.5' }}>
                {selectedCase.description || 'No initial description provided.'}
              </p>
            </div>

            {/* Extracted IOCs */}
            <div>
              <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600, marginBottom: '6px' }}>
                Indicators of Compromise (IOCs)
              </div>
              <div style={{
                backgroundColor: '#0b0f19',
                border: '1px solid #1f2937',
                borderRadius: '8px',
                padding: '10px 14px',
                fontFamily: 'monospace',
                fontSize: '12px',
                color: '#f87171',
                lineHeight: '1.5',
              }}>
                {selectedCase.ioc_list || 'No IOCs cataloged.'}
              </div>
            </div>

            {/* Analyst Findings & Narrative Editor */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>
                  Analyst Findings & Evidence Narrative
                </span>
                <span style={{ fontSize: '11px', color: '#64748b' }}>Auto-synced to pcapman.db</span>
              </div>
              <textarea
                value={editFindings}
                onChange={(e) => setEditFindings(e.target.value)}
                placeholder="Write your forensic analysis notes, packet stream observations, and remediation steps here..."
                rows={8}
                style={{
                  width: '100%',
                  backgroundColor: '#0b0f19',
                  border: '1px solid #334155',
                  borderRadius: '10px',
                  padding: '12px',
                  color: '#f8fafc',
                  fontSize: '13px',
                  fontFamily: 'inherit',
                  lineHeight: '1.5',
                  outline: 'none',
                  resize: 'vertical',
                }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Create Case Modal */}
      {isCreateOpen && (
        <div
          onClick={() => setIsCreateOpen(false)}
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
              maxWidth: '560px',
              width: '100%',
              maxHeight: 'calc(100vh - 40px)',
              overflowY: 'auto',
              padding: '24px',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                Initiate Forensic Investigation
              </h3>
              <button
                onClick={() => setIsCreateOpen(false)}
                style={{ background: 'transparent', border: 'none', color: '#64748b', fontSize: '20px', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateCase} style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '18px' }}>
              <div>
                <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
                  Case Title
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Cobalt Strike DNS Tunneling Detection"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  style={{
                    width: '100%',
                    backgroundColor: '#0b0f19',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    color: '#f8fafc',
                    fontSize: '13px',
                    outline: 'none',
                  }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
                    Severity
                  </label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    style={{
                      width: '100%',
                      backgroundColor: '#0b0f19',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                      padding: '8px 12px',
                      color: '#f8fafc',
                      fontSize: '13px',
                      outline: 'none',
                    }}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
                    Lead Analyst
                  </label>
                  <input
                    type="text"
                    value={newAnalyst}
                    onChange={(e) => setNewAnalyst(e.target.value)}
                    style={{
                      width: '100%',
                      backgroundColor: '#0b0f19',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                      padding: '8px 12px',
                      color: '#f8fafc',
                      fontSize: '13px',
                      outline: 'none',
                    }}
                  />
                </div>
              </div>

              <div>
                <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
                  Linked Capture Evidence
                </label>
                <select
                  value={newCaptureId}
                  onChange={(event) => setNewCaptureId(event.target.value)}
                  style={{ width: '100%', backgroundColor: '#0b0f19', border: '1px solid #334155', borderRadius: '8px', padding: '8px 12px', color: '#f8fafc', fontSize: '13px' }}
                >
                  <option value="">No capture linked</option>
                  {captures.filter((capture) => capture.status === 'analyzed').map((capture) => (
                    <option key={capture.id} value={capture.id}>{capture.filename} ({capture.packet_count} packets)</option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
                  Initial Hypothesis & Incident Scope
                </label>
                <textarea
                  rows={3}
                  placeholder="Describe initial packet anomalies and affected internal endpoints..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  style={{
                    width: '100%',
                    backgroundColor: '#0b0f19',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    color: '#f8fafc',
                    fontSize: '13px',
                    outline: 'none',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '12px', color: '#94a3b8', display: 'block', marginBottom: '4px' }}>
                  Known Indicators of Compromise (IOCs)
                </label>
                <input
                  type="text"
                  placeholder="e.g. 185.220.101.5, malicious-domain.com, /api/v1/beacon"
                  value={newIoc}
                  onChange={(e) => setNewIoc(e.target.value)}
                  style={{
                    width: '100%',
                    backgroundColor: '#0b0f19',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '8px 12px',
                    color: '#f8fafc',
                    fontSize: '13px',
                    outline: 'none',
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  style={{
                    backgroundColor: '#1e293b',
                    color: '#cbd5e1',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    padding: '8px 16px',
                    fontSize: '13px',
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    backgroundColor: '#f59e0b',
                    color: '#0b0f19',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '8px 18px',
                    fontSize: '13px',
                    fontWeight: 700,
                    cursor: 'pointer',
                  }}
                >
                  Open Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
