import type { CheckStatus, RiskLevel } from '@/types';

export function riskClass(level?: string): string {
  const normalized = (level || '').toUpperCase();
  if (normalized === 'CRITICAL') return 'risk-badge risk-critical';
  if (normalized === 'HIGH') return 'risk-badge risk-high';
  if (normalized === 'MEDIUM') return 'risk-badge risk-medium';
  return 'risk-badge risk-low';
}

export function statusClass(status?: CheckStatus | string): string {
  const normalized = (status || '').toUpperCase();
  if (normalized === 'FAIL') return 'status-badge status-fail';
  if (normalized === 'WARN') return 'status-badge status-warn';
  if (normalized === 'INFO') return 'status-badge status-info';
  if (normalized === 'SKIP') return 'status-badge status-skip';
  return 'status-badge status-pass';
}

export function levelFromScore(score: number): RiskLevel {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}
