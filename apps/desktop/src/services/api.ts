/**
 * PCAP-MAN API Service Layer
 * Connects to FastAPI backend at http://localhost:8000
 * Uses the local FastAPI service as the source of truth.
 */

export const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

// ── Response Types ─────────────────────────────────────────────

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'error';
  application: string;
  version?: string;
  uptime_seconds?: number;
  tshark_detected?: boolean;
  timestamp?: string;
}

export interface CaptureRecord {
  id: string;
  filename: string;
  file_size_bytes: number;
  file_type: string;
  sha256: string;
  md5?: string;
  packet_count: number;
  flow_count: number;
  duration_seconds: number;
  status: 'registered' | 'processing' | 'analyzed' | 'failed';
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface SystemStats {
  captures: number;
  hosts: number;
  flows: number;
  investigations: number;
  total_bytes?: number;
  total_packets?: number;
  tshark_available?: boolean;
}

export interface FlowRecord {
  id: string;
  flow_key: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  application: string;
  packet_count: number;
  bytes_total: number;
  bytes_forward: number;
  bytes_reverse: number;
  start_time: string | null;
  end_time: string | null;
  duration_seconds?: number;
  tcp_flags: string;
  summary: string;
  capture_filename?: string;
  payload_hex_preview?: string;
}

export interface HostRecord {
  ip: string;
  mac: string;
  hostname: string;
  role: string;
  open_ports: number[];
  bytes_total: number;
  bytes_sent: number;
  bytes_received: number;
  packet_count: number;
  risk_score?: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface TimelineEventRecord {
  id: string;
  timestamp: string;
  event_type: string;
  protocol: string;
  src: string;
  dst: string;
  severity: 'info' | 'warning' | 'high' | 'critical';
  category: string;
  description: string;
  capture_filename?: string;
}

export interface DnsRecord {
  id: string;
  capture_id: string;
  flow_id?: string | null;
  timestamp: string;
  query_name: string;
  query_type: string;
  response_code?: string | null;
  answers?: string | null;
  ttl?: number | null;
}

export interface HttpRequestRecord {
  id: string;
  capture_id: string;
  flow_id?: string | null;
  timestamp: string;
  method: string;
  host?: string | null;
  url: string;
  path?: string | null;
  user_agent?: string | null;
  status_code?: number | null;
  response_phrase?: string | null;
  content_type?: string | null;
}

export interface TlsRecord {
  id: string;
  capture_id: string;
  flow_id?: string | null;
  timestamp: string;
  version: string;
  sni?: string | null;
  cipher_suite?: string | null;
  alpn?: string | null;
}

export interface CertificateRecord {
  id: string;
  capture_id: string;
  flow_id?: string | null;
  fingerprint_sha256: string;
  subject_cn?: string | null;
  subject_org?: string | null;
  issuer_cn?: string | null;
  issuer_org?: string | null;
  valid_from?: string | null;
  valid_to?: string | null;
  serial_number?: string | null;
  san_list?: string | null;
  is_self_signed: boolean;
}

export interface ProtocolDistributionItem {
  category: string;
  protocol: string;
  application: string;
  flow_count: number;
  packet_count: number;
  byte_count: number;
  percentage: number;
}

export interface ProtocolStatsRecord {
  total_dns: number;
  total_http: number;
  total_tls: number;
  total_certificates: number;
  total_flows: number;
  protocol_distribution: ProtocolDistributionItem[];
  dns_stats: {
    total_queries: number;
    total_responses: number;
    by_type: Record<string, number>;
    by_response_code: Record<string, number>;
    top_domains: Array<{ name: string; count: number }>;
  };
  http_stats: {
    by_method: Record<string, number>;
    by_status: Record<string, number>;
    top_hosts: Array<{ host: string; count: number }>;
    top_user_agents: Array<{ user_agent: string; count: number }>;
    content_types: Record<string, number>;
  };
  tls_stats: {
    by_version: Record<string, number>;
    top_sni: Array<{ sni: string; count: number }>;
    top_ciphers: Array<{ cipher: string; count: number }>;
    top_alpn: Array<{ alpn: string; count: number }>;
  };
  certificate_stats: {
    total_certs: number;
    self_signed_count: number;
    expired_count: number;
    valid_count: number;
    top_issuers: Array<{ issuer: string; count: number }>;
  };
}

export interface InvestigationCaseRecord {
  id: string;
  title: string;
  case_number: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'under_review' | 'escalated' | 'closed';
  lead_analyst: string;
  description?: string;
  findings?: string;
  ioc_list?: string;
  linked_capture_ids?: string;
  capture_count?: number;
  flow_count?: number;
  event_count?: number;
  created_at: string;
  updated_at: string;
}

export type BackendStatus = 'online' | 'offline' | 'checking';

// ── HTTP Client ────────────────────────────────────────────────

async function apiFetch<T>(
  path: string,
  options?: RequestInit,
  timeoutMs = 5000
): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      let message = `HTTP ${response.status}: ${response.statusText}`;
      try {
        const body = await response.json();
        message = body.error?.message || body.detail || message;
      } catch {
        // Keep the HTTP status when the server does not return JSON.
      }
      throw new Error(message);
    }

    return (await response.json()) as T;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ── API Methods ────────────────────────────────────────────────

/**
 * Check the health of the FastAPI backend.
 * GET /health
 */
export async function checkBackendHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>('/health');
}

/**
 * Probe backend connectivity without throwing.
 * Returns 'online' | 'offline'.
 */
export async function probeBackend(): Promise<BackendStatus> {
  try {
    const health = await checkBackendHealth();
    return health.status === 'healthy' ? 'online' : 'offline';
  } catch {
    return 'offline';
  }
}

/**
 * Aggregated system statistics.
 * GET /api/v1/stats
 */
export async function getSystemStats(): Promise<SystemStats> {
  return apiFetch<SystemStats>('/api/v1/stats');
}

/**
 * List all captures.
 * GET /api/v1/captures
 */
export async function getCaptures(): Promise<CaptureRecord[]> {
  return apiFetch<CaptureRecord[]>('/api/v1/captures');
}

/**
 * Upload and register a PCAP/PCAPNG evidence file.
 * POST /api/v1/captures/upload
 */
export async function uploadCapture(file: File, onProgress?: (percent: number) => void): Promise<CaptureRecord> {
  const formData = new FormData();
  formData.append('file', file);
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', `${API_BASE}/api/v1/captures/upload`);
    request.responseType = 'json';
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress?.(Math.round((event.loaded / event.total) * 100));
    };
    request.onload = () => {
      if (request.status >= 200 && request.status < 300) resolve(request.response as CaptureRecord);
      else reject(new Error(request.response?.error?.message || request.response?.detail || `Upload failed (${request.status})`));
    };
    request.onerror = () => reject(new Error('Could not connect to the PCAP-MAN backend'));
    request.send(formData);
  });
}

/**
 * Delete a capture by ID.
 * DELETE /api/v1/captures/{id}
 */
export async function deleteCapture(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/v1/captures/${id}`, { method: 'DELETE' });
  if (!response.ok) throw new Error(`Could not delete capture (${response.status})`);
}

// ── Phase 3: Flow & Network Intelligence API ────────────────────

/**
 * Fetch extracted network conversation flows.
 * GET /api/v1/flows
 */
export async function getFlows(params?: {
  protocol?: string;
  search?: string;
  captureId?: string;
  limit?: number;
}): Promise<{ total: number; flows: FlowRecord[] }> {
  const query = new URLSearchParams();
  if (params?.protocol) query.set('protocol', params.protocol);
  if (params?.search) query.set('search', params.search);
  if (params?.captureId) query.set('capture_id', params.captureId);
  if (params?.limit) query.set('limit', String(params.limit));
  const path = `/api/v1/flows${query.toString() ? `?${query.toString()}` : ''}`;
  return apiFetch<{ total: number; flows: FlowRecord[] }>(path);
}

/**
 * Fetch single flow detail with payload preview.
 * GET /api/v1/flows/{id}
 */
export async function getFlowDetail(id: string): Promise<FlowRecord> {
  return await apiFetch<FlowRecord>(`/api/v1/flows/${id}`);
}

/**
 * Fetch discovered host profiles.
 * GET /api/v1/hosts
 */
export async function getHosts(search?: string, captureId?: string): Promise<{ total: number; hosts: HostRecord[] }> {
  const query = new URLSearchParams();
  if (search) query.set('search', search);
  if (captureId) query.set('capture_id', captureId);
  const path = `/api/v1/hosts${query.toString() ? `?${query.toString()}` : ''}`;
  return apiFetch<{ total: number; hosts: HostRecord[] }>(path);
}

/**
 * Fetch chronological forensic timeline events.
 * GET /api/v1/timeline
 */
export async function getTimelineEvents(params?: {
  category?: string;
  severity?: string;
  search?: string;
  captureId?: string;
  protocol?: string;
  investigationId?: string;
}): Promise<{ total: number; events: TimelineEventRecord[] }> {
  const query = new URLSearchParams();
  if (params?.protocol) query.set('protocol', params.protocol);
  if (params?.investigationId) query.set('investigation_id', params.investigationId);
  if (params?.category) query.set('category', params.category);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.search) query.set('search', params.search);
  if (params?.captureId) query.set('capture_id', params.captureId);
  const path = `/api/v1/timeline${query.toString() ? `?${query.toString()}` : ''}`;
  return apiFetch<{ total: number; events: TimelineEventRecord[] }>(path);
}

// ── Phase 4: Investigation & Case Management API ────────────────

/**
 * List all investigation cases.
 * GET /api/v1/investigations
 */
export async function getInvestigations(): Promise<InvestigationCaseRecord[]> {
  return apiFetch<InvestigationCaseRecord[]>('/api/v1/investigations');
}

/**
 * Create a new forensic case.
 * POST /api/v1/investigations
 */
export async function createInvestigation(data: {
  title: string;
  severity: string;
  lead_analyst: string;
  description?: string;
  findings?: string;
  ioc_list?: string;
  linked_capture_ids?: string[];
}): Promise<InvestigationCaseRecord> {
  const response = await fetch(`${API_BASE}/api/v1/investigations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('Failed to create investigation case');
  return (await response.json()) as InvestigationCaseRecord;
}

/**
 * Update case notes, findings, status, or severity.
 * PATCH /api/v1/investigations/{id}
 */
export async function updateInvestigation(
  id: string,
  data: Partial<InvestigationCaseRecord>
): Promise<InvestigationCaseRecord> {
  const response = await fetch(`${API_BASE}/api/v1/investigations/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('Failed to update case');
  return (await response.json()) as InvestigationCaseRecord;
}

/**
 * Delete an investigation case.
 * DELETE /api/v1/investigations/{id}
 */
export async function deleteInvestigation(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/v1/investigations/${id}`, { method: 'DELETE' });
  if (!response.ok) throw new Error(`Could not delete investigation (${response.status})`);
}

// ── Phase 4: Timeline summary, correlation and case evidence ────

export interface TimelineSummary {
  total: number;
  by_severity: Record<'critical' | 'high' | 'warning' | 'info', number>;
  by_category: { category: string; count: number }[];
}

export interface RelatedTimelineEvent {
  relation: 'same_flow' | 'same_host';
  event: TimelineEventRecord;
}

export interface InvestigationEvidenceRecord {
  captures: CaptureRecord[];
  flows: FlowRecord[];
  events: TimelineEventRecord[];
}

/**
 * Real counts per severity and category.
 * GET /api/v1/timeline/summary
 */
export async function getTimelineSummary(params?: { captureId?: string; investigationId?: string }): Promise<TimelineSummary> {
  const query = new URLSearchParams();
  if (params?.captureId) query.set('capture_id', params.captureId);
  if (params?.investigationId) query.set('investigation_id', params.investigationId);
  return apiFetch<TimelineSummary>(`/api/v1/timeline/summary${query.toString() ? `?${query.toString()}` : ''}`);
}

/**
 * Events correlated with one event (same flow, or same hosts within a time window).
 * GET /api/v1/timeline/{id}/related
 */
export async function getRelatedEvents(eventId: string, windowSeconds = 60): Promise<{ event_id: string; total: number; related: RelatedTimelineEvent[] }> {
  return apiFetch(`/api/v1/timeline/${eventId}/related?window_seconds=${windowSeconds}`);
}

/**
 * Captures, flows and timeline events linked to a case.
 * GET /api/v1/investigations/{id}/evidence
 */
export async function getInvestigationEvidence(caseId: string): Promise<InvestigationEvidenceRecord> {
  return apiFetch<InvestigationEvidenceRecord>(`/api/v1/investigations/${caseId}/evidence`);
}

/**
 * The case's own timeline (linked events plus events of linked flows).
 * GET /api/v1/investigations/{id}/timeline
 */
export async function getInvestigationTimeline(caseId: string, includeCaptures = false): Promise<{ total: number; events: TimelineEventRecord[] }> {
  return apiFetch(`/api/v1/investigations/${caseId}/timeline?include_captures=${includeCaptures}`);
}

/**
 * Attach captures, flows and timeline events to a case.
 * POST /api/v1/investigations/{id}/evidence
 */
export async function linkInvestigationEvidence(
  caseId: string,
  evidence: { capture_ids?: string[]; flow_ids?: string[]; event_ids?: string[] },
): Promise<InvestigationCaseRecord> {
  const response = await fetch(`${API_BASE}/api/v1/investigations/${caseId}/evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(evidence),
  });
  if (!response.ok) {
    const detail = await response.json().then((body) => body?.error?.message).catch(() => undefined);
    throw new Error(detail || `Could not link evidence (${response.status})`);
  }
  return response.json();
}

/**
 * Remove one piece of evidence from a case.
 * DELETE /api/v1/investigations/{id}/evidence/{captures|flows|events}/{evidenceId}
 */
export async function unlinkInvestigationEvidence(caseId: string, kind: 'captures' | 'flows' | 'events', evidenceId: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/v1/investigations/${caseId}/evidence/${kind}/${evidenceId}`, { method: 'DELETE' });
  if (!response.ok) throw new Error(`Could not remove evidence (${response.status})`);
}

// ── Platform Settings & Diagnostics ────────────────────────────

export interface SystemSettingsRecord {
  app_name: string;
  app_version: string;
  host: string;
  port: number;
  tshark_detected: boolean;
  tshark_binary_path: string;
  evidence_directory: string;
  database_path: string;
  database_size_bytes: number;
  python_version: string;
  os_platform: string;
  cpu_count: number;
}

export async function getPlatformSettings(): Promise<SystemSettingsRecord> {
  return apiFetch<SystemSettingsRecord>('/api/v1/settings');
}

// ── Phase 6: Intelligence Briefing & Executive Reporting ────────

export interface BriefingReportRecord {
  report_id: string;
  classification: string;
  generated_at: string;
  case_number: string;
  case_title: string;
  lead_analyst: string;
  organization: string;
  executive_summary: string;
  case_findings: string;
  kill_chain: Array<{ phase: string; observation: string; status: string }>;
  iocs: Array<{ type: string; value: string; attribution: string; reputation: string }>;
  evidence_records: Array<{ filename: string; sha256: string; packet_count: number; size_kb: number }>;
  recommendations: string[];
}

export async function generateBriefingReport(caseId?: string): Promise<BriefingReportRecord> {
  const query = caseId ? `?case_id=${encodeURIComponent(caseId)}` : '';
  return apiFetch<BriefingReportRecord>(`/api/v1/briefings/generate${query}`);
}

// ── Phase 3: Protocol Intelligence & Deep Packet Inspection API ──

/**
 * Fetch extracted DNS records.
 * GET /api/v1/dns
 */
export async function getDnsRecords(params?: {
  captureId?: string;
  queryType?: string;
  search?: string;
  limit?: number;
}): Promise<DnsRecord[]> {
  const query = new URLSearchParams();
  if (params?.captureId) query.set('capture_id', params.captureId);
  if (params?.queryType) query.set('query_type', params.queryType);
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  const path = `/api/v1/dns${query.toString() ? `?${query.toString()}` : ''}`;
  return apiFetch<DnsRecord[]>(path);
}

/**
 * Fetch extracted HTTP request/response transactions.
 * GET /api/v1/http
 */
export async function getHttpRequests(params?: {
  captureId?: string;
  method?: string;
  search?: string;
  limit?: number;
}): Promise<HttpRequestRecord[]> {
  const query = new URLSearchParams();
  if (params?.captureId) query.set('capture_id', params.captureId);
  if (params?.method) query.set('method', params.method);
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  const path = `/api/v1/http${query.toString() ? `?${query.toString()}` : ''}`;
  return apiFetch<HttpRequestRecord[]>(path);
}

/**
 * Fetch extracted TLS handshake metadata.
 * GET /api/v1/tls
 */
export async function getTlsRecords(params?: {
  captureId?: string;
  version?: string;
  search?: string;
  limit?: number;
}): Promise<TlsRecord[]> {
  const query = new URLSearchParams();
  if (params?.captureId) query.set('capture_id', params.captureId);
  if (params?.version) query.set('version', params.version);
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  const path = `/api/v1/tls${query.toString() ? `?${query.toString()}` : ''}`;
  return apiFetch<TlsRecord[]>(path);
}

/**
 * Fetch extracted X.509 certificates.
 * GET /api/v1/certificates
 */
export async function getCertificates(params?: {
  captureId?: string;
  selfSigned?: boolean;
  search?: string;
  limit?: number;
}): Promise<CertificateRecord[]> {
  const query = new URLSearchParams();
  if (params?.captureId) query.set('capture_id', params.captureId);
  if (params?.selfSigned !== undefined) query.set('self_signed', String(params.selfSigned));
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  const path = `/api/v1/certificates${query.toString() ? `?${query.toString()}` : ''}`;
  return apiFetch<CertificateRecord[]>(path);
}

/**
 * Fetch aggregated protocol intelligence statistics and categorization.
 * GET /api/v1/protocols/stats
 */
export async function getProtocolStats(captureId?: string): Promise<ProtocolStatsRecord> {
  const query = captureId ? `?capture_id=${encodeURIComponent(captureId)}` : '';
  return apiFetch<ProtocolStatsRecord>(`/api/v1/protocols/stats${query}`);
}

