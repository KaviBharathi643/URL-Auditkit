import type {
  AuditResponse,
  DashboardOverview,
  IOCRecord,
  PagedResponse,
  ScanMode,
  ScanRecord,
  ThreatMapPoint,
  WebSocketMessage,
} from '@/types';

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8765';

export interface RunAuditOptions {
  url: string;
  scanMode: ScanMode;
  onProgress?: (message: WebSocketMessage) => void;
}

async function fetchJSON<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    method: 'GET',
    cache: 'no-store',
  });
  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`);
  }
  return response.json();
}

export async function runAudit(options: RunAuditOptions): Promise<AuditResponse> {
  const jobId = crypto.randomUUID();
  const ws = new WebSocket(`${WS_URL}/ws/progress/${jobId}`);

  ws.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data) as WebSocketMessage;
      options.onProgress?.(payload);
      if (payload.type === 'complete' || payload.type === 'error') {
        ws.close();
      }
    } catch {
      // no-op
    }
  };

  const formData = new FormData();
  formData.append('url', options.url);
  formData.append('job_id', jobId);
  formData.append('scan_mode', options.scanMode);

  const response = await fetch('/api/audit', {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    ws.close();
    throw new Error(`Audit failed (${response.status})`);
  }

  const payload = (await response.json()) as AuditResponse;
  ws.close();
  return payload;
}

export async function getDashboardOverview(range: string): Promise<DashboardOverview> {
  return fetchJSON<DashboardOverview>(`/api/dashboard/overview?range=${encodeURIComponent(range)}`);
}

export async function getScans(params: {
  page: number;
  pageSize: number;
  q: string;
  risk: string;
  status: string;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
}): Promise<PagedResponse<ScanRecord>> {
  const searchParams = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
    q: params.q,
    risk: params.risk,
    status: params.status,
    sort_by: params.sortBy,
    sort_order: params.sortOrder,
  });
  return fetchJSON<PagedResponse<ScanRecord>>(`/api/scans?${searchParams.toString()}`);
}

export async function getScan(scanId: number): Promise<ScanRecord & { checks: any[]; iocs: IOCRecord[] }> {
  return fetchJSON(`/api/scans/${scanId}`);
}

export async function getScanReport(scanId: number): Promise<any> {
  return fetchJSON(`/api/scans/${scanId}/report`);
}

export async function getIOCs(params: {
  page: number;
  pageSize: number;
  q: string;
  type: string;
  severity: string;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
}): Promise<PagedResponse<IOCRecord>> {
  const searchParams = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
    q: params.q,
    type: params.type,
    severity: params.severity,
    sort_by: params.sortBy,
    sort_order: params.sortOrder,
  });
  return fetchJSON<PagedResponse<IOCRecord>>(`/api/iocs?${searchParams.toString()}`);
}

export async function getThreatMap(range: string): Promise<{ points: ThreatMapPoint[] }> {
  return fetchJSON(`/api/threat-intelligence/map?range=${encodeURIComponent(range)}`);
}

export async function getThreatDomains(limit = 20): Promise<{ items: Array<{ domain: string; hits: number; last_seen: string }> }> {
  return fetchJSON(`/api/threat-intelligence/domains?limit=${limit}`);
}

export async function getThreatIpReputation(
  limit = 20
): Promise<{ items: Array<{ ip: string; sightings: number; critical_hits: number; high_hits: number; medium_hits: number; last_seen: string }> }> {
  return fetchJSON(`/api/threat-intelligence/ip-reputation?limit=${limit}`);
}
