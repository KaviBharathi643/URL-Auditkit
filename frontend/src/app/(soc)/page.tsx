'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import DataTable from '@/components/ui/DataTable';
import { getDashboardOverview, getScans } from '@/lib/api';
import { riskClass } from '@/lib/risk';
import type { DashboardOverview, PagedResponse, ScanRecord } from '@/types';

const EMPTY_OVERVIEW: DashboardOverview = {
  range: '24h',
  totals: {
    total_scans: 0,
    malicious_urls: 0,
    suspicious_domains: 0,
    safe_urls: 0,
  },
  threat_distribution: [],
  scan_activity: [],
  recent_scans: [],
};

const PIE_COLORS: Record<string, string> = {
  LOW: '#10b981',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
  CRITICAL: '#ff355d',
};

function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function DashboardPage() {
  const [range, setRange] = useState('24h');
  const [overview, setOverview] = useState<DashboardOverview>(EMPTY_OVERVIEW);
  const [overviewLoading, setOverviewLoading] = useState(true);

  const [rows, setRows] = useState<PagedResponse<ScanRecord>>({
    items: [],
    total: 0,
    page: 1,
    page_size: 10,
    total_pages: 1,
  });
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const loadOverview = useCallback(async () => {
    setOverviewLoading(true);
    try {
      const payload = await getDashboardOverview(range);
      setOverview(payload);
    } catch {
      setOverview(EMPTY_OVERVIEW);
    } finally {
      setOverviewLoading(false);
    }
  }, [range]);

  const loadScans = useCallback(
    async (page: number, q = query, sortKey = sortBy, direction = sortOrder) => {
      try {
        const payload = await getScans({
          page,
          pageSize: 10,
          q,
          risk: '',
          status: '',
          sortBy: sortKey,
          sortOrder: direction,
        });
        setRows(payload);
      } catch {
        setRows((prev) => ({ ...prev, items: [] }));
      }
    },
    [query, sortBy, sortOrder]
  );

  useEffect(() => {
    loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    loadScans(1);
  }, [loadScans]);

  const activityGraphData = useMemo(
    () =>
      overview.scan_activity.map((item) => ({
        ...item,
        label: item.bucket.slice(5),
      })),
    [overview.scan_activity]
  );

  return (
    <div className="page-grid">
      <section className="panel page-heading">
        <div>
          <p className="eyebrow">SOC Overview</p>
          <h1>Threat Visibility Dashboard</h1>
          <p className="subtitle">Operational visibility across scans, malicious indicators, and risk trends.</p>
        </div>
        <div className="button-row">
          {['24h', '7d', '30d'].map((value) => (
            <button
              key={value}
              className={`segmented-button ${range === value ? 'active' : ''}`}
              onClick={() => setRange(value)}
            >
              {value}
            </button>
          ))}
        </div>
      </section>

      <section className="kpi-grid">
        <article className="panel stat-card glow-soft">
          <p>Total Scans</p>
          <strong className={overviewLoading ? 'shimmer-line' : ''}>{overview.totals.total_scans}</strong>
        </article>
        <article className="panel stat-card glow-danger">
          <p>Malicious URLs</p>
          <strong className={overviewLoading ? 'shimmer-line' : ''}>{overview.totals.malicious_urls}</strong>
        </article>
        <article className="panel stat-card glow-warning">
          <p>Suspicious Domains</p>
          <strong className={overviewLoading ? 'shimmer-line' : ''}>{overview.totals.suspicious_domains}</strong>
        </article>
        <article className="panel stat-card glow-success">
          <p>Safe URLs</p>
          <strong className={overviewLoading ? 'shimmer-line' : ''}>{overview.totals.safe_urls}</strong>
        </article>
      </section>

      <section className="charts-grid">
        <article className="panel">
          <h2>Threat Distribution</h2>
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={overview.threat_distribution}
                  dataKey="value"
                  nameKey="label"
                  innerRadius={62}
                  outerRadius={92}
                  paddingAngle={4}
                >
                  {overview.threat_distribution.map((entry) => (
                    <Cell key={entry.label} fill={PIE_COLORS[entry.label]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="legend-row">
            {overview.threat_distribution.map((item) => (
              <span key={item.label} className={`legend-item ${riskClass(item.label)}`}>
                {item.label}: {item.value}
              </span>
            ))}
          </div>
        </article>

        <article className="panel">
          <h2>Scan Activity Timeline</h2>
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={activityGraphData}>
                <defs>
                  <linearGradient id="scanActivityFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.7} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.08} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" />
                <XAxis dataKey="label" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip />
                <Area type="monotone" dataKey="total" stroke="#06b6d4" fill="url(#scanActivityFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </article>

        <article className="panel">
          <h2>Malicious vs Safe</h2>
          <div className="chart-box">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={activityGraphData}>
                <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" />
                <XAxis dataKey="label" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="malicious" fill="#ef4444" radius={[4, 4, 0, 0]} />
                <Bar dataKey="safe" fill="#10b981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </article>
      </section>

      <DataTable<ScanRecord>
        title={overviewLoading ? 'Recent Scans (loading...)' : 'Recent Scans'}
        columns={[
          {
            key: 'target_url',
            label: 'URL',
            sortable: true,
            render: (row) => <span className="url-cell">{row.target_url}</span>,
          },
          {
            key: 'risk_score',
            label: 'Risk Score',
            sortable: true,
            render: (row) => row.risk_score,
          },
          {
            key: 'risk_level',
            label: 'Status',
            sortable: true,
            render: (row) => <span className={riskClass(row.risk_level)}>{row.risk_level}</span>,
          },
          {
            key: 'created_at',
            label: 'Timestamp',
            sortable: true,
            render: (row) => formatTimestamp(row.created_at),
          },
        ]}
        rows={rows.items}
        filterValue={query}
        onFilterChange={(value) => {
          setQuery(value);
          loadScans(1, value);
        }}
        filterPlaceholder="Filter by URL..."
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSort={(key) => {
          const nextOrder: 'asc' | 'desc' = sortBy === key && sortOrder === 'desc' ? 'asc' : 'desc';
          setSortBy(key);
          setSortOrder(nextOrder);
          loadScans(1, query, key, nextOrder);
        }}
        page={rows.page}
        totalPages={rows.total_pages}
        totalRows={rows.total}
        onPageChange={(page) => loadScans(page)}
        emptyMessage="No scan results available."
      />
    </div>
  );
}
