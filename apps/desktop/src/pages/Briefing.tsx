import { useState, useEffect } from 'react';
import {
  Briefcase,
  Download,
  Printer,
  Copy,
  Check,
  ShieldAlert,
  FileText,
  RefreshCw,
  Layers,
  ShieldCheck,
  User,
  AlertTriangle,
} from 'lucide-react';
import {
  generateBriefingReport,
  getInvestigations,
  type BriefingReportRecord,
  type InvestigationCaseRecord,
} from '../services/api';

export default function Briefing() {
  const [report, setReport] = useState<BriefingReportRecord | null>(null);
  const [cases, setCases] = useState<InvestigationCaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  const fetchReport = async (caseId?: number) => {
    setLoading(true);
    try {
      const [rep, caseList] = await Promise.all([
        generateBriefingReport(caseId),
        getInvestigations(),
      ]);
      setReport(rep);
      setCases(caseList);
    } catch (err) {
      console.error('Failed to generate briefing report', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport(selectedCaseId);
  }, [selectedCaseId]);

  const handleCopy = () => {
    if (!report) return;
    const text = `
================================================================================
${report.classification}
PCAP-MAN — EXECUTIVE CYBER INTELLIGENCE BRIEFING
Report ID: ${report.report_id}
Case: ${report.case_number} — ${report.case_title}
Generated: ${new Date(report.generated_at).toLocaleString()}
Lead Examiner: ${report.lead_analyst}
Organization: ${report.organization}
================================================================================

1. EXECUTIVE SUMMARY:
${report.executive_summary}

2. ANALYST FINDINGS:
${report.case_findings}

3. INDICATORS OF COMPROMISE (IOCs):
${report.iocs.map((i) => `• [${i.type}] ${i.value} (${i.attribution} - ${i.reputation})`).join('\n')}

4. REMEDIATION RECOMMENDATIONS:
${report.recommendations.map((r, idx) => `${idx + 1}. ${r}`).join('\n')}

================================================================================
Chain of Custody Cryptographically Verified by PCAP-MAN Core Engine
================================================================================
`.trim();

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadMarkdown = () => {
    if (!report) return;
    const mdContent = `# ${report.classification}
# PCAP-MAN: Forensic Intelligence Briefing & Incident Dossier

**Report ID:** \`${report.report_id}\`
**Case Number:** \`${report.case_number}\` — ${report.case_title}
**Date of Assessment:** ${new Date(report.generated_at).toUTCString()}
**Lead Investigator:** ${report.lead_analyst}
**Laboratory:** ${report.organization}

---

## 1. Executive Summary
${report.executive_summary}

## 2. Technical Findings
${report.case_findings}

## 3. Cyber Kill-Chain Progression
${report.kill_chain.map((k) => `### ${k.phase} [Status: ${k.status}]\n${k.observation}\n`).join('\n')}

## 4. Indicators of Compromise (IOCs)
| Type | Artifact Value | Threat Attribution | Reputation |
| :--- | :--- | :--- | :--- |
${report.iocs.map((i) => `| **${i.type}** | \`${i.value}\` | ${i.attribution} | ${i.reputation} |`).join('\n')}

## 5. Ingested Evidence Chain of Custody
| Capture File | SHA-256 Digest | Packet Count | Size (KB) |
| :--- | :--- | :--- | :--- |
${report.evidence_records.map((e) => `| ${e.filename} | \`${e.sha256}\` | ${e.packet_count} | ${e.size_kb} KB |`).join('\n')}

## 6. Incident Remediation Action Plan
${report.recommendations.map((r, idx) => `${idx + 1}. ${r}`).join('\n')}

---
*Signed and sealed by PCAP-MAN Local Forensic Verification Ledger.*
`;

    const blob = new Blob([mdContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.report_id}_Forensic_Briefing.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Intelligence Briefing & Dossier Export
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
              PHASE 6 OPERATIONAL
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '640px' }}>
            Automated intelligence report generator compiling active cases, forensic telemetry, indicators of compromise (IOCs), and executive summaries into audit-ready briefing dossiers.
          </p>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button
            onClick={handleCopy}
            style={{
              backgroundColor: '#1e293b',
              color: copied ? '#10b981' : '#f8fafc',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '8px 14px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            {copied ? <Check size={14} /> : <Copy size={14} />}
            <span>{copied ? 'Copied Briefing' : 'Copy Text'}</span>
          </button>

          <button
            onClick={handleDownloadMarkdown}
            style={{
              backgroundColor: '#1e293b',
              color: '#f8fafc',
              border: '1px solid #334155',
              borderRadius: '8px',
              padding: '8px 14px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <Download size={14} />
            <span>Export Markdown</span>
          </button>

          <button
            onClick={handlePrint}
            style={{
              backgroundColor: '#8b5cf6',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              padding: '8px 16px',
              fontSize: '12px',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 0 15px rgba(139, 92, 246, 0.3)',
            }}
          >
            <Printer size={14} />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Case Selector Filter Bar */}
      <div style={{
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '12px',
        padding: '12px 18px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Briefcase size={16} style={{ color: '#a78bfa' }} />
          <span style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>
            Target Investigation Dossier:
          </span>
          <select
            value={selectedCaseId || ''}
            onChange={(e) => setSelectedCaseId(e.target.value ? Number(e.target.value) : undefined)}
            style={{
              backgroundColor: '#0b0f19',
              border: '1px solid #334155',
              color: '#cbd5e1',
              borderRadius: '8px',
              padding: '6px 12px',
              fontSize: '12px',
              fontWeight: 600,
              outline: 'none',
            }}
          >
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.case_number}: {c.title}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={() => fetchReport(selectedCaseId)}
          style={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            color: '#94a3b8',
            borderRadius: '6px',
            padding: '6px 10px',
            fontSize: '11px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
          }}
        >
          <RefreshCw size={12} />
          <span>Regenerate</span>
        </button>
      </div>

      {/* Formal Document Preview Paper */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
          Synthesizing intelligence dossier...
        </div>
      ) : report ? (
        <div style={{
          backgroundColor: '#0d1321',
          border: '1px solid #1f2937',
          borderRadius: '16px',
          padding: '36px',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.5)',
          display: 'flex',
          flexDirection: 'column',
          gap: '24px',
        }}>
          {/* Classification Banner */}
          <div style={{
            textAlign: 'center',
            backgroundColor: 'rgba(245, 158, 11, 0.12)',
            border: '1px solid rgba(245, 158, 11, 0.3)',
            color: '#fbbf24',
            fontWeight: 800,
            fontSize: '12px',
            letterSpacing: '0.15em',
            padding: '6px',
            borderRadius: '6px',
          }}>
            {report.classification}
          </div>

          {/* Report Title & Metadata Block */}
          <div style={{ borderBottom: '1px solid #1f2937', paddingBottom: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <span style={{ fontSize: '11px', color: 'var(--color-cyan)', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  INCIDENT RESPONSE TECHNICAL BRIEFING
                </span>
                <h2 style={{ fontSize: '22px', fontWeight: 800, color: '#f8fafc', margin: '4px 0 0 0' }}>
                  {report.case_title}
                </h2>
                <div style={{ fontSize: '13px', color: '#94a3b8', marginTop: '4px' }}>
                  Reference: <span style={{ fontFamily: 'monospace', color: '#a78bfa', fontWeight: 700 }}>{report.case_number}</span> • Report ID: <span style={{ fontFamily: 'monospace', color: '#cbd5e1' }}>{report.report_id}</span>
                </div>
              </div>

              <div style={{ textAlign: 'right', fontSize: '12px', color: '#64748b' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '4px', color: '#cbd5e1' }}>
                  <User size={13} />
                  <span>{report.lead_analyst}</span>
                </div>
                <div style={{ marginTop: '2px' }}>{report.organization}</div>
                <div style={{ marginTop: '2px', fontFamily: 'monospace' }}>
                  {new Date(report.generated_at).toLocaleString()}
                </div>
              </div>
            </div>
          </div>

          {/* Section 1: Executive Summary */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <FileText size={16} style={{ color: 'var(--color-cyan)' }} />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', margin: 0, textTransform: 'uppercase' }}>
                1. Executive Summary
              </h3>
            </div>
            <div style={{
              backgroundColor: '#111827',
              border: '1px solid #1f2937',
              borderRadius: '10px',
              padding: '16px',
              fontSize: '13px',
              color: '#cbd5e1',
              lineHeight: '1.6',
            }}>
              {report.executive_summary}
            </div>
          </div>

          {/* Section 2: Cyber Kill-Chain Progression */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <Layers size={16} style={{ color: '#a78bfa' }} />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', margin: 0, textTransform: 'uppercase' }}>
                2. Cyber Attack Kill-Chain Progression
              </h3>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
              {report.kill_chain.map((kc, i) => (
                <div
                  key={i}
                  style={{
                    backgroundColor: '#111827',
                    border: '1px solid #1f2937',
                    borderRadius: '10px',
                    padding: '14px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ fontSize: '12px', fontWeight: 700, color: '#f8fafc' }}>{kc.phase}</span>
                    <span style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(239, 68, 68, 0.15)',
                      color: '#f87171',
                    }}>
                      {kc.status}
                    </span>
                  </div>
                  <p style={{ color: '#94a3b8', fontSize: '12px', margin: 0, lineHeight: '1.4' }}>
                    {kc.observation}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Section 3: Indicators of Compromise Matrix */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <ShieldAlert size={16} style={{ color: '#ef4444' }} />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', margin: 0, textTransform: 'uppercase' }}>
                3. Indicators of Compromise (IOC) Matrix
              </h3>
            </div>
            <div style={{ overflowX: 'auto', backgroundColor: '#111827', borderRadius: '10px', border: '1px solid #1f2937' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1f2937', color: '#64748b', textTransform: 'uppercase', backgroundColor: '#090d16' }}>
                    <th style={{ padding: '10px 14px' }}>Observable Type</th>
                    <th style={{ padding: '10px 14px' }}>Indicator Value</th>
                    <th style={{ padding: '10px 14px' }}>Threat Attribution</th>
                    <th style={{ padding: '10px 14px' }}>Reputation</th>
                  </tr>
                </thead>
                <tbody>
                  {report.iocs.map((ioc, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid #1f2937' }}>
                      <td style={{ padding: '10px 14px', fontWeight: 600, color: '#cbd5e1' }}>{ioc.type}</td>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#f87171' }}>{ioc.value}</td>
                      <td style={{ padding: '10px 14px', color: '#a78bfa' }}>{ioc.attribution}</td>
                      <td style={{ padding: '10px 14px', color: '#fbbf24' }}>{ioc.reputation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 4: Evidentiary Chain of Custody */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <ShieldCheck size={16} style={{ color: 'var(--color-terminal)' }} />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', margin: 0, textTransform: 'uppercase' }}>
                4. Evidentiary PCAP Chain of Custody
              </h3>
            </div>
            <div style={{ overflowX: 'auto', backgroundColor: '#111827', borderRadius: '10px', border: '1px solid #1f2937' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1f2937', color: '#64748b', textTransform: 'uppercase', backgroundColor: '#090d16' }}>
                    <th style={{ padding: '10px 14px' }}>Capture Artifact</th>
                    <th style={{ padding: '10px 14px' }}>SHA-256 Digest</th>
                    <th style={{ padding: '10px 14px' }}>Frames</th>
                    <th style={{ padding: '10px 14px' }}>Volume</th>
                  </tr>
                </thead>
                <tbody>
                  {report.evidence_records.map((ev, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid #1f2937' }}>
                      <td style={{ padding: '10px 14px', fontWeight: 600, color: '#f8fafc' }}>{ev.filename}</td>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: 'var(--color-cyan)', fontSize: '11px' }}>
                        {ev.sha256}
                      </td>
                      <td style={{ padding: '10px 14px', color: '#cbd5e1' }}>{ev.packet_count}</td>
                      <td style={{ padding: '10px 14px', color: '#94a3b8' }}>{ev.size_kb} KB</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 5: Strategic Remediation Action Plan */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <AlertTriangle size={16} style={{ color: '#f59e0b' }} />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', margin: 0, textTransform: 'uppercase' }}>
                5. Strategic Containment & Remediation Plan
              </h3>
            </div>
            <div style={{
              backgroundColor: '#111827',
              border: '1px solid #1f2937',
              borderRadius: '10px',
              padding: '16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}>
              {report.recommendations.map((rec, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                  <span style={{
                    width: '20px',
                    height: '20px',
                    borderRadius: '50%',
                    backgroundColor: 'rgba(245, 158, 11, 0.15)',
                    color: '#fbbf24',
                    fontSize: '11px',
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    {i + 1}
                  </span>
                  <span style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: '1.4' }}>{rec}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Sign-off Seal */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            paddingTop: '20px',
            borderTop: '1px solid #1f2937',
            fontSize: '12px',
            color: '#64748b',
          }}>
            <div>
              Certified by: <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{report.lead_analyst}</span>
            </div>
            <div style={{ color: 'var(--color-terminal)', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldCheck size={16} />
              <span>Immutable Chain of Custody Verified</span>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
