'use client';

import { useEffect, useState } from 'react';
import { getDashboardOverview } from '@/lib/api';

interface QuickStats {
  total_scans: number;
  malicious_urls: number;
  suspicious_domains: number;
  safe_urls: number;
}

const initialStats: QuickStats = {
  total_scans: 0,
  malicious_urls: 0,
  suspicious_domains: 0,
  safe_urls: 0,
};

export default function RightRail() {
  const [stats, setStats] = useState<QuickStats>(initialStats);

  useEffect(() => {
    let active = true;
    getDashboardOverview('24h')
      .then((payload) => {
        if (active) {
          setStats(payload.totals);
        }
      })
      .catch(() => {
        if (active) {
          setStats(initialStats);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <aside className="soc-right-rail">
      <section className="panel panel-glass">
        <h3>Threat Summary</h3>
        <div className="rail-metric-grid">
          <div>
            <p>Total Scans</p>
            <strong>{stats.total_scans}</strong>
          </div>
          <div>
            <p>Malicious</p>
            <strong className="text-danger">{stats.malicious_urls}</strong>
          </div>
          <div>
            <p>Suspicious</p>
            <strong className="text-warning">{stats.suspicious_domains}</strong>
          </div>
          <div>
            <p>Safe</p>
            <strong className="text-success">{stats.safe_urls}</strong>
          </div>
        </div>
      </section>

      <section className="panel panel-glass">
        <h3>Live Alerts</h3>
        <ul className="alerts-list">
          <li>
            <span className="risk-badge risk-critical">CRITICAL</span>
            <span>Blacklist hit detected in latest scan</span>
          </li>
          <li>
            <span className="risk-badge risk-high">HIGH</span>
            <span>Safe Browsing warning observed</span>
          </li>
          <li>
            <span className="risk-badge risk-medium">MEDIUM</span>
            <span>Suspicious redirect chain in history</span>
          </li>
        </ul>
      </section>
    </aside>
  );
}
