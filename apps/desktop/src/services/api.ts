/**
 * PCAP-MAN API Service Layer
 * Connects to FastAPI backend at http://localhost:8000
 * Uses the local FastAPI service as the source of truth.
 */

export const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

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
  start_time: string;
  end_time: string;
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
  first_seen: string;
  last_seen: string;
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
  limit?: number;
}): Promise<{ total: number; flows: FlowRecord[] }> {
  const query = new URLSearchParams();
  if (params?.protocol) query.set('protocol', params.protocol);
  if (params?.search) query.set('search', params.search);
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
export async function getHosts(search?: string): Promise<{ total: number; hosts: HostRecord[] }> {
  const query = search ? `?search=${encodeURIComponent(search)}` : '';
  return apiFetch<{ total: number; hosts: HostRecord[] }>(`/api/v1/hosts${query}`);
}

/**
 * Fetch chronological forensic timeline events.
 * GET /api/v1/timeline
 */
export async function getTimelineEvents(params?: {
  category?: string;
  severity?: string;
  search?: string;
}): Promise<{ total: number; events: TimelineEventRecord[] }> {
  const query = new URLSearchParams();
  if (params?.category) query.set('category', params.category);
  if (params?.severity) query.set('severity', params.severity);
  if (params?.search) query.set('search', params.search);
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


