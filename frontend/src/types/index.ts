export type CheckStatus = 'PASS' | 'WARN' | 'FAIL' | 'INFO' | 'SKIP';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Verdict = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';

export interface CheckResult {
  id: number;
  name: string;
  status: CheckStatus;
  evidence: string;
  details?: string;
  data?: Record<string, any>;
  summary?: string;
  risk_level?: RiskLevel;
  section?: string;
}

export interface ThreatReport {
  executive_summary: string;
  key_findings: string[];
  verdict: Verdict;
  verdict_rationale: string;
  recommendations: string[];
}

export interface AIMetadata {
  generator: string;
  model: string;
  timestamp: string;
}

export interface AuditResponse {
  results: CheckResult[];
  summary_cards: SummaryCard[];
  target_url: string;
  total_checks: number;
  ai_threat_report?: ThreatReport;
  ai_metadata?: AIMetadata;
  ai_error?: string;
  grouped_results?: GroupedResult[];
  scan_id?: number;
  scan_mode?: ScanMode;
  risk_score?: number;
  risk_level?: RiskLevel;
  verdict?: Verdict;
  duration_ms?: number;
  created_at?: string;
  ioc_count?: number;
}

export interface SummaryCard {
  status: CheckStatus;
  count: number;
}

export interface GroupedResult {
  name: string;
  checks: CheckResult[];
}

export interface WebSocketMessage {
  type: 'start' | 'progress' | 'complete' | 'error';
  step?: number;
  total?: number;
  percent?: number;
  label?: string;
  message?: string;
}

export type ScanMode = 'scan' | 'deep' | 'sandbox';

export interface ScanRecord {
  id: number;
  target_url: string;
  scan_mode: ScanMode;
  risk_score: number;
  risk_level: RiskLevel;
  verdict: Verdict;
  total_checks: number;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  info_count: number;
  skip_count: number;
  ai_verdict?: Verdict | null;
  ai_summary?: string | null;
  duration_ms: number;
  created_at: string;
}

export interface ThreatMapPoint {
  country: string;
  lat: number;
  lng: number;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface IOCRecord {
  id: number;
  scan_id: number;
  indicator: string;
  indicator_type: string;
  severity: RiskLevel;
  source_check: string;
  country?: string | null;
  created_at: string;
  target_url?: string;
  risk_level?: RiskLevel;
  risk_score?: number;
}

export interface PagedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface DashboardOverview {
  range: '24h' | '7d' | '30d' | string;
  totals: {
    total_scans: number;
    malicious_urls: number;
    suspicious_domains: number;
    safe_urls: number;
  };
  threat_distribution: Array<{
    label: RiskLevel;
    value: number;
  }>;
  scan_activity: Array<{
    bucket: string;
    total: number;
    malicious: number;
    safe: number;
  }>;
  recent_scans: Array<{
    id: number;
    target_url: string;
    risk_score: number;
    risk_level: RiskLevel;
    verdict: Verdict;
    created_at: string;
  }>;
}
