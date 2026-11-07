import { useState, useEffect } from 'react';
import {
  Activity,
  Search,
  Bookmark,
  BookmarkCheck,
  AlertTriangle,
  ShieldAlert,
  Clock,
  ArrowRight,
  Download,
} from 'lucide-react';
import { getTimelineEvents, type TimelineEventRecord } from '../services/api';

export default function Timeline() {
  const [events, setEvents] = useState<TimelineEventRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [bookmarkedIds, setBookmarkedIds] = useState<Set<number>>(new Set());

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const res = await getTimelineEvents({
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        category: categoryFilter !== 'ALL' ? categoryFilter : undefined,
        search: searchTerm || undefined,
      });
      setEvents(res.events);
    } catch (err) {
      console.error('Failed to load timeline events', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [severityFilter, categoryFilter]);

  const toggleBookmark = (id: number) => {
    setBookmarkedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleExportTimeline = () => {
    const jsonStr = JSON.stringify(events, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pcapman_forensic_timeline_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const criticalCount = events.filter((e) => e.severity === 'critical').length;
  const highCount = events.filter((e) => e.severity === 'high').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em', color: '#f8fafc', margin: 0 }}>
              Chronological Event Reconstruction
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
              PHASE 3 OPERATIONAL
            </span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px', maxWidth: '640px' }}>
            Sequential timeline reconstruction of all network interactions. Correlates DNS queries, TLS handshakes, HTTP requests, and lateral movements in microsecond order.
          </p>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={handleExportTimeline}
            style={{
              backgroundColor: '#1e293b',
              color: '#f8fafc',
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
            <Download size={14} />
            <span>Export Timeline (JSON)</span>
          </button>
        </div>
      </div>

      {/* KPI & Filters Bar */}
      <div style={{
        backgroundColor: '#111827',
        border: '1px solid #1f2937',
        borderRadius: '12px',
        padding: '14px 18px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '14px',
      }}>
        {/* Severity Badges & Critical Alerts */}
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: '4px', alignItems: 'center', backgroundColor: '#0b0f19', padding: '2px', borderRadius: '8px', border: '1px solid #1f2937' }}>
            {['ALL', 'critical', 'high', 'warning', 'info'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  backgroundColor: severityFilter === sev ? (sev === 'critical' ? '#ef4444' : sev === 'high' ? '#f97316' : sev === 'warning' ? '#f59e0b' : '#06b6d4') : 'transparent',
                  color: severityFilter === sev ? '#0b0f19' : '#94a3b8',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '4px 10px',
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', gap: '4px', alignItems: 'center', backgroundColor: '#0b0f19', padding: '2px', borderRadius: '8px', border: '1px solid #1f2937' }}>
            {['ALL', 'Resolution', 'Encryption', 'C2 Traffic', 'Lateral Movement'].map((cat) => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                style={{
                  backgroundColor: categoryFilter === cat ? '#8b5cf6' : 'transparent',
                  color: categoryFilter === cat ? '#ffffff' : '#94a3b8',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '4px 8px',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {cat}
              </button>
            ))}
          </div>

          {(criticalCount > 0 || highCount > 0) && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '11px',
              fontWeight: 700,
              padding: '4px 8px',
              borderRadius: '6px',
              backgroundColor: 'rgba(239, 68, 68, 0.15)',
              color: '#f87171',
              border: '1px solid rgba(239, 68, 68, 0.3)',
            }}>
              <ShieldAlert size={13} />
              <span>{criticalCount + highCount} Threat Detections</span>
            </div>
          )}
        </div>

        {/* Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
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
              placeholder="Search event narrative..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchEvents()}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#f8fafc',
                fontSize: '13px',
                outline: 'none',
                width: '180px',
              }}
            />
          </div>

          <button
            onClick={fetchEvents}
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
            Search
          </button>
        </div>
      </div>

      {/* Timeline Stream */}
      <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Continuous timeline vertical line */}
        <div style={{
          position: 'absolute',
          left: '23px',
          top: '20px',
          bottom: '20px',
          width: '2px',
          backgroundColor: '#1f2937',
          zIndex: 0,
        }} />

        {loading ? (
          <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>
            Reconstructing event chronology...
          </div>
        ) : events.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }}>
            <Activity size={36} style={{ color: '#475569', marginBottom: '10px' }} />
            <p>No timeline events match the filter parameters.</p>
          </div>
        ) : (
          events.map((ev) => {
            const isCritical = ev.severity === 'critical';
            const isHigh = ev.severity === 'high';
            const isWarning = ev.severity === 'warning';
            const isBookmarked = bookmarkedIds.has(ev.id);

            const badgeBg = isCritical
              ? 'rgba(239, 68, 68, 0.15)'
              : isHigh
              ? 'rgba(249, 115, 22, 0.15)'
              : isWarning
              ? 'rgba(245, 158, 11, 0.15)'
              : 'rgba(6, 182, 212, 0.15)';

            const badgeColor = isCritical
              ? '#f87171'
              : isHigh
              ? '#fb923c'
              : isWarning
              ? '#fbbf24'
              : '#22d3ee';

            return (
              <div
                key={ev.id}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '16px',
                  position: 'relative',
                  zIndex: 1,
                }}
              >
                {/* Node Bullet */}
                <div style={{
                  width: '46px',
                  height: '46px',
                  borderRadius: '50%',
                  backgroundColor: '#111827',
                  border: `2px solid ${badgeColor}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  boxShadow: `0 0 10px ${badgeColor}33`,
                }}>
                  {isCritical ? (
                    <ShieldAlert size={20} style={{ color: badgeColor }} />
                  ) : isHigh || isWarning ? (
                    <AlertTriangle size={20} style={{ color: badgeColor }} />
                  ) : (
                    <Activity size={20} style={{ color: badgeColor }} />
                  )}
                </div>

                {/* Event Card */}
                <div style={{
                  backgroundColor: '#111827',
                  border: `1px solid ${isBookmarked ? 'var(--color-cyan)' : '#1f2937'}`,
                  borderRadius: '12px',
                  padding: '16px 20px',
                  flex: 1,
                  boxShadow: isCritical ? '0 0 20px rgba(239, 68, 68, 0.08)' : 'none',
                }}>
                  {/* Top Row: Time, Type, Severity, Bookmark */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        backgroundColor: badgeBg,
                        color: badgeColor,
                      }}>
                        {ev.severity}
                      </span>

                      <span style={{
                        fontSize: '11px',
                        fontFamily: 'monospace',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        backgroundColor: '#1e293b',
                        color: '#94a3b8',
                      }}>
                        {ev.protocol}
                      </span>

                      <span style={{ fontSize: '12px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <Clock size={12} />
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <button
                      onClick={() => toggleBookmark(ev.id)}
                      title={isBookmarked ? 'Remove Bookmark' : 'Bookmark for Investigation Report'}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: isBookmarked ? 'var(--color-cyan)' : '#64748b',
                        cursor: 'pointer',
                        padding: '4px',
                      }}
                    >
                      {isBookmarked ? <BookmarkCheck size={18} /> : <Bookmark size={18} />}
                    </button>
                  </div>

                  {/* Flow Endpoints */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    color: '#94a3b8',
                    marginTop: '10px',
                  }}>
                    <span style={{ color: '#38bdf8' }}>{ev.src}</span>
                    <ArrowRight size={13} style={{ color: '#64748b' }} />
                    <span style={{ color: '#f8fafc' }}>{ev.dst}</span>
                  </div>

                  {/* Narrative Description */}
                  <div style={{
                    fontSize: '14px',
                    color: isCritical ? '#fca5a5' : '#e2e8f0',
                    fontWeight: isCritical ? 600 : 400,
                    marginTop: '8px',
                    lineHeight: '1.4',
                  }}>
                    {ev.description}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
