'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import DataTable from '@/components/ui/DataTable';
import { getScans } from '@/lib/api';
import { riskClass } from '@/lib/risk';
import type { PagedResponse, ScanRecord } from '@/types';

export default function HistoryPage() {
  const [rows, setRows] = useState<PagedResponse<ScanRecord>>({
    items: [],
    total: 0,
    page: 1,
    page_size: 20,
    total_pages: 1,
  });
  const [query, setQuery] = useState('');
  const [risk, setRisk] = useState('');
  const [status, setStatus] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const load = useCallback(
    async (page: number, nextQuery = query, nextSortBy = sortBy, nextSortOrder = sortOrder) => {
      try {
        const payload = await getScans({
          page,
          pageSize: 20,
          q: nextQuery,
          risk,
          status,
          sortBy: nextSortBy,
          sortOrder: nextSortOrder,
        });
        setRows(payload);
      } catch {
        setRows((prev) => ({ ...prev, items: [] }));
      }
    },
    [query, sortBy, sortOrder, risk, status]
  );

  useEffect(() => {
    load(1);
  }, [load]);

  return (
    <div className="page-grid">
      <section className="panel page-heading">
        <div>
          <p className="eyebrow">Scan History</p>
          <h1>Historical Investigation Timeline</h1>
          <p className="subtitle">Review completed scans, pivot to reports, and rerun investigation workflows.</p>
        </div>
        <div className="filters-inline">
          <select aria-label="Risk filter" value={risk} onChange={(event) => setRisk(event.target.value)}>
            <option value="">All Risk</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
          <select aria-label="Verdict filter" value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">All Verdicts</option>
            <option value="BENIGN">BENIGN</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="MALICIOUS">MALICIOUS</option>
          </select>
          <button className="secondary-button" onClick={() => load(1)}>
            Apply
          </button>
        </div>
      </section>

      <DataTable<ScanRecord>
        title="Scan Records"
        columns={[
          { key: 'id', label: 'ID', sortable: true, render: (row) => row.id },
          {
            key: 'target_url',
            label: 'URL',
            sortable: true,
            render: (row) => <span className="url-cell">{row.target_url}</span>,
          },
          { key: 'scan_mode', label: 'Mode', sortable: true, render: (row) => row.scan_mode.toUpperCase() },
          { key: 'risk_score', label: 'Risk', sortable: true, render: (row) => row.risk_score },
          {
            key: 'risk_level',
            label: 'Level',
            sortable: true,
            render: (row) => <span className={riskClass(row.risk_level)}>{row.risk_level}</span>,
          },
          {
            key: 'created_at',
            label: 'Timestamp',
            sortable: true,
            render: (row) => new Date(row.created_at).toLocaleString(),
          },
          {
            key: 'actions',
            label: 'Actions',
            render: (row) => (
              <div className="action-links">
                <Link href={`/reports/${row.id}`}>Report</Link>
                <Link href={`/scanner?url=${encodeURIComponent(row.target_url)}`}>Re-scan</Link>
              </div>
            ),
          },
        ]}
        rows={rows.items}
        filterValue={query}
        onFilterChange={(value) => {
          setQuery(value);
          load(1, value);
        }}
        filterPlaceholder="Search URL..."
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSort={(key) => {
          const nextOrder: 'asc' | 'desc' = sortBy === key && sortOrder === 'desc' ? 'asc' : 'desc';
          setSortBy(key);
          setSortOrder(nextOrder);
          load(1, query, key, nextOrder);
        }}
        page={rows.page}
        totalPages={rows.total_pages}
        totalRows={rows.total}
        onPageChange={(page) => load(page)}
        emptyMessage="No scan history found."
      />
    </div>
  );
}
