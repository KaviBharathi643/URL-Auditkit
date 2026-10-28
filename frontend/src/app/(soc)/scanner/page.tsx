'use client';

import { FormEvent, useEffect, useMemo, useState, type CSSProperties } from 'react';
import { motion } from 'framer-motion';
import { runAudit } from '@/lib/api';
import { riskClass, statusClass } from '@/lib/risk';
import type { AuditResponse, CheckResult, ScanMode } from '@/types';

function checkByPattern(results: CheckResult[], pattern: string): CheckResult | undefined {
  return results.find((result) => result.name.toLowerCase().includes(pattern.toLowerCase()));
}

function parseValue(evidence: string, key: string): string {
  const regex = new RegExp(`${key}=([^\\s,]+)`, 'i');
  const match = evidence.match(regex);
  return match?.[1] || 'unknown';
}

export default function ScannerPage() {
  const [url, setUrl] = useState('');
  const [scanMode, setScanMode] = useState<ScanMode>('scan');
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState('Preparing scan...');
  const [error, setError] = useState('');
  const [result, setResult] = useState<AuditResponse | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const initialUrl = params.get('url');
    if (initialUrl) {
      setUrl(initialUrl);
    }
  }, []);

  const threatTags = useMemo(() => {
    if (!result?.results) return [];
    return result.results
      .filter((check) => check.status === 'FAIL' || check.status === 'WARN')
      .slice(0, 8)
      .map((check) => check.name);
  }, [result]);

  const domainCheck = result ? checkByPattern(result.results, 'domain') : undefined;
  const sslCheck = result ? checkByPattern(result.results, 'ssl') : undefined;
  const geolocationCheck = result ? checkByPattern(result.results, 'geolocation') : undefined;
  const ipReputationCheck = result ? checkByPattern(result.results, 'ip reputation') : undefined;
  const blacklistCheck = result ? checkByPattern(result.results, 'blacklist') : undefined;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError('');
    setResult(null);

    if (!url.trim()) {
      setError('Enter a URL to scan.');
      return;
    }

    setRunning(true);
    setProgress(0);
    setProgressLabel('Initializing analysis...');

    try {
      const payload = await runAudit({
        url,
        scanMode,
        onProgress: (message) => {
          setProgress(message.percent ?? 0);
          setProgressLabel(message.label || 'Scanning...');
          if (message.type === 'error') {
            setError(message.message || 'Scan failed');
          }
        },
      });
      setResult(payload);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : 'Scan failed');
    } finally {
      setRunning(false);
    }
  }

  const score = result?.risk_score ?? 0;
  const riskLevel = result?.risk_level || 'LOW';

  return (
    <div className="page-grid">
      <section className="panel page-heading">
        <div>
          <p className="eyebrow">URL Scanner</p>
          <h1>Real-time Threat Analysis Console</h1>
          <p className="subtitle">Run standard, deep, or sandbox-oriented URL analysis with live SOC telemetry.</p>
        </div>
      </section>

      <section className="panel scan-input-panel">
        <form onSubmit={handleSubmit}>
          <label htmlFor="scan-url">Target URL</label>
          <textarea
            id="scan-url"
            className="scan-textarea"
            placeholder="https://example.com"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            rows={3}
          />

          <div className="button-row">
            {[
              { value: 'scan', label: 'Scan URL' },
              { value: 'deep', label: 'Deep Scan' },
              { value: 'sandbox', label: 'Sandbox Analysis' },
            ].map((mode) => (
              <button
                key={mode.value}
                type="button"
                className={`segmented-button ${scanMode === mode.value ? 'active' : ''}`}
                onClick={() => setScanMode(mode.value as ScanMode)}
              >
                {mode.label}
              </button>
            ))}
          </div>

          <div className="button-row">
            <button type="submit" className="primary-button" disabled={running}>
              {running ? 'Scanning...' : 'Execute Scan'}
            </button>
          </div>

          {error && <p className="error-text">{error}</p>}
        </form>
      </section>

      {running && (
        <motion.section className="panel scan-overlay-panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <div className="radar-wrap" aria-hidden>
            <span className="radar-ring ring-1" />
            <span className="radar-ring ring-2" />
            <span className="radar-ring ring-3" />
            <span className="radar-sweep" />
          </div>
          <div>
            <h2>Scanning in Progress</h2>
            <p>{progressLabel}</p>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${progress}%` }} />
            </div>
            <strong>{progress}%</strong>
          </div>
        </motion.section>
      )}

      {result && (
        <>
          <section className="scan-summary-grid">
            <article className="panel">
              <h2>Risk Score Gauge</h2>
              <div className="risk-gauge" style={{ '--risk-value': `${score}` } as CSSProperties}>
                <div className="risk-gauge-inner">
                  <strong>{score}</strong>
                  <span className={riskClass(riskLevel)}>{riskLevel}</span>
                </div>
              </div>
            </article>

            <article className="panel">
              <h2>Threat Tags</h2>
              <div className="tag-cloud">
                {threatTags.length === 0 && <span className="risk-badge risk-low">No active threat tags</span>}
                {threatTags.map((tag) => (
                  <span key={tag} className="risk-badge risk-medium">
                    {tag}
                  </span>
                ))}
              </div>
            </article>

            <article className="panel">
              <h2>Domain Intelligence</h2>
              <ul className="details-list">
                <li>
                  <span>Domain Info</span>
                  <span className={statusClass(domainCheck?.status)}>{domainCheck?.status || 'N/A'}</span>
                </li>
                <li>
                  <span>SSL Status</span>
                  <span className={statusClass(sslCheck?.status)}>{sslCheck?.status || 'N/A'}</span>
                </li>
                <li>
                  <span>IP Location</span>
                  <span>{parseValue(geolocationCheck?.evidence || '', 'country')}</span>
                </li>
                <li>
                  <span>IP Reputation</span>
                  <span className={statusClass(ipReputationCheck?.status)}>{ipReputationCheck?.status || 'N/A'}</span>
                </li>
                <li>
                  <span>Blacklist Matches</span>
                  <span className={statusClass(blacklistCheck?.status)}>{blacklistCheck?.status || 'N/A'}</span>
                </li>
              </ul>
            </article>
          </section>

          <section className="panel">
            <h2>Analysis Cards</h2>
            <div className="analysis-grid">
              {result.results.map((check) => (
                <article key={`${check.id}-${check.name}`} className="analysis-card">
                  <div className="analysis-card-header">
                    <span className={statusClass(check.status)}>{check.status}</span>
                    <span className={riskClass(check.risk_level)}>{check.risk_level || 'LOW'}</span>
                  </div>
                  <h3>{check.name}</h3>
                  <p>{check.summary || check.evidence || 'No evidence provided.'}</p>
                  {check.evidence && <code>{check.evidence}</code>}
                </article>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
