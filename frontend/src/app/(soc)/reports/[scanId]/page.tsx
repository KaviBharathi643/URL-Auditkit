'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { getScanReport } from '@/lib/api';
import { riskClass, statusClass } from '@/lib/risk';

interface ReportPayload {
  scan_summary: {
    target_url: string;
    scan_mode: string;
    risk_score: number;
    risk_level: string;
    verdict: string;
    created_at: string;
    duration_ms: number;
    total_checks: number;
  };
  indicators_of_compromise: Array<{
    id: number;
    indicator: string;
    indicator_type: string;
    severity: string;
    source_check: string;
    country?: string | null;
  }>;
  domain_intelligence: Array<{
    id: number;
    name: string;
    status: string;
    summary: string;
    evidence: string;
    details?: string;
    data?: Record<string, unknown>;
    section?: string;
  }>;
  risk_assessment: {
    pass_count: number;
    warn_count: number;
    fail_count: number;
    info_count: number;
    skip_count: number;
    risk_score: number;
    risk_level: string;
  };
  recommendations: string[];
  grouped_checks: Array<{
    name: string;
    checks: Array<{
      id: number;
      name: string;
      status: string;
      risk_level: string;
      summary: string;
      evidence: string;
      details?: string;
      data?: Record<string, unknown>;
      section?: string;
    }>;
  }>;
}

function findDomainCheck(payload: ReportPayload, pattern: string) {
  return payload.domain_intelligence.find((check) => check.name.toLowerCase().includes(pattern.toLowerCase()));
}

export default function ReportDetailPage() {
  const params = useParams<{ scanId: string }>();
  const scanId = Number(params.scanId);
  const [payload, setPayload] = useState<ReportPayload | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!Number.isFinite(scanId)) return;
    getScanReport(scanId)
      .then((data) => setPayload(data))
      .catch(() => setError('Failed to load report.'));
  }, [scanId]);

  if (error) {
    return (
      <div className="page-grid">
        <section className="panel">
          <p className="error-text">{error}</p>
        </section>
      </div>
    );
  }

  if (!payload) {
    return (
      <div className="page-grid">
        <section className="panel">
          <p>Loading report...</p>
        </section>
      </div>
    );
  }

  const domainLegitimacy = findDomainCheck(payload, 'domain name legitimacy');
  const domainAge = findDomainCheck(payload, 'whois and domain age');
  const domainExpiry = findDomainCheck(payload, 'domain expiry');

  return (
    <div className="page-grid">
      <section className="panel page-heading">
        <div>
          <p className="eyebrow">Scan Report</p>
          <h1>Report #{scanId}</h1>
          <p className="subtitle">{payload.scan_summary.target_url}</p>
        </div>
        <div className="button-row">
          <span className={riskClass(payload.scan_summary.risk_level)}>{payload.scan_summary.risk_level}</span>
          <span className="risk-badge risk-medium">{payload.scan_summary.verdict}</span>
        </div>
      </section>

      <section className="report-grid">
        <article className="panel">
          <h2>Scan Summary</h2>
          <ul className="details-list">
            <li>
              <span>Mode</span>
              <span>{payload.scan_summary.scan_mode.toUpperCase()}</span>
            </li>
            <li>
              <span>Risk Score</span>
              <span>{payload.scan_summary.risk_score}</span>
            </li>
            <li>
              <span>Total Checks</span>
              <span>{payload.scan_summary.total_checks}</span>
            </li>
            <li>
              <span>Duration</span>
              <span>{payload.scan_summary.duration_ms} ms</span>
            </li>
            <li>
              <span>Generated</span>
              <span>{new Date(payload.scan_summary.created_at).toLocaleString()}</span>
            </li>
          </ul>
        </article>

        <article className="panel">
          <h2>Risk Assessment</h2>
          <ul className="details-list">
            <li>
              <span>PASS</span>
              <span className={statusClass('PASS')}>{payload.risk_assessment.pass_count}</span>
            </li>
            <li>
              <span>WARN</span>
              <span className={statusClass('WARN')}>{payload.risk_assessment.warn_count}</span>
            </li>
            <li>
              <span>FAIL</span>
              <span className={statusClass('FAIL')}>{payload.risk_assessment.fail_count}</span>
            </li>
            <li>
              <span>INFO</span>
              <span className={statusClass('INFO')}>{payload.risk_assessment.info_count}</span>
            </li>
            <li>
              <span>SKIP</span>
              <span className={statusClass('SKIP')}>{payload.risk_assessment.skip_count}</span>
            </li>
          </ul>
        </article>
      </section>

      <section className="panel">
        <h2>Indicators of Compromise</h2>
        <div className="indicator-list">
          {payload.indicators_of_compromise.map((ioc) => (
            <article key={ioc.id} className="indicator-item">
              <div>
                <strong>{ioc.indicator}</strong>
                <p>
                  {ioc.indicator_type} · {ioc.source_check} {ioc.country ? `· ${ioc.country}` : ''}
                </p>
              </div>
              <span className={riskClass(ioc.severity)}>{ioc.severity}</span>
            </article>
          ))}
          {payload.indicators_of_compromise.length === 0 && <p>No IOCs extracted.</p>}
        </div>
      </section>

      <section className="panel">
        <h2>Domain Intelligence</h2>
        <ul className="details-list" style={{ marginBottom: 12 }}>
          <li>
            <span>Legitimacy</span>
            <span className={statusClass(domainLegitimacy?.status || 'SKIP')}>
              {domainLegitimacy?.status || 'N/A'}
            </span>
          </li>
          <li>
            <span>WHOIS / Domain Age</span>
            <span className={statusClass(domainAge?.status || 'SKIP')}>{domainAge?.status || 'N/A'}</span>
          </li>
          <li>
            <span>Domain Expiry</span>
            <span className={statusClass(domainExpiry?.status || 'SKIP')}>{domainExpiry?.status || 'N/A'}</span>
          </li>
        </ul>
        <div className="analysis-grid">
          {payload.domain_intelligence.map((check) => (
            <article key={`${check.id}-${check.name}`} className="analysis-card">
              <div className="analysis-card-header">
                <span className={statusClass(check.status)}>{check.status}</span>
              </div>
              <h3>{check.name}</h3>
              <p>{check.summary || check.evidence}</p>
              {check.evidence && <code>{check.evidence}</code>}
              {check.details && (
                <details style={{ marginTop: 10 }}>
                  <summary>Technical details</summary>
                  <pre>{check.details}</pre>
                </details>
              )}
            </article>
          ))}
          {payload.domain_intelligence.length === 0 && <p>No domain intelligence checks available.</p>}
        </div>
      </section>

      <section className="panel">
        <h2>All Checks ({payload.scan_summary.total_checks})</h2>
        <div className="page-grid">
          {payload.grouped_checks.map((group) => (
            <section key={group.name} className="panel-glass" style={{ padding: 12 }}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 10,
                }}
              >
                <h3 style={{ margin: 0 }}>{group.name}</h3>
                <span className="risk-badge risk-medium">{group.checks.length} checks</span>
              </div>
              <div className="analysis-grid">
                {group.checks.map((check) => (
                  <article key={`${group.name}-${check.id}-${check.name}`} className="analysis-card">
                    <div className="analysis-card-header">
                      <span className={statusClass(check.status)}>{check.status}</span>
                      <span className={riskClass(check.risk_level || 'LOW')}>{check.risk_level || 'LOW'}</span>
                    </div>
                    <h3>{check.name}</h3>
                    <p>{check.summary || check.evidence || 'No summary available.'}</p>
                    {check.evidence && <code>{check.evidence}</code>}
                    {check.details && (
                      <details style={{ marginTop: 10 }}>
                        <summary>Technical details</summary>
                        <pre>{check.details}</pre>
                      </details>
                    )}
                  </article>
                ))}
              </div>
            </section>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Recommendations</h2>
        <ul className="recommendation-list">
          {payload.recommendations.map((recommendation) => (
            <li key={recommendation}>{recommendation}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
