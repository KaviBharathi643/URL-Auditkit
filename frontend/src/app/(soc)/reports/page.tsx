'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import DataTable from '@/components/ui/DataTable';
import { getScans } from '@/lib/api';
import { riskClass } from '@/lib/risk';
import type { PagedResponse, ScanRecord } from '@/types';

export default function ReportsPage() {
  const [rows, setRows] = useState<PagedResponse<ScanRecord>>({
    items: [],
    total: 0,
    page: 1,
    page_size: 15,
    total_pages: 1,
  });
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const load = useCallback(
    async (page: number, q = query, nextSortBy = sortBy, nextSortOrder = sortOrder) => {
      try {
        const payload = await getScans({
          page,
          pageSize: 15,
          q,
          risk: '',
          status: '',
          sortBy: nextSortBy,
          sortOrder: nextSortOrder,
        });
        setRows(payload);
      } catch {
        setRows((prev) => ({ ...prev, items: [] }));
      }
    },
    [query, sortBy, sortOrder]
  );

  useEffect(() => {
    load(1);
  }, [load]);

  return (
    <div className="page-grid">
      <section className="panel page-heading">
        <div>
          <p className="eyebrow">Reports</p>
          <h1>Cybersecurity Report Workspace</h1>
          <p className="subtitle">Open detailed SOC reports generated for each completed URL investigation.</p>
        </div>
      </section>

      <DataTable<ScanRecord>
        title="Generated Reports"
        columns={[
          { key: 'id', label: 'Report ID', sortable: true, render: (row) => row.id },
          { key: 'target_url', label: 'Target URL', sortable: true, render: (row) => row.target_url },
          {
            key: 'risk_level',
            label: 'Risk',
            sortable: true,
            render: (row) => <span className={riskClass(row.risk_level)}>{row.risk_level}</span>,
          },
          {
            key: 'verdict',
            label: 'Verdict',
            sortable: true,
            render: (row) => row.verdict,
          },
          {
            key: 'created_at',
            label: 'Generated',
            sortable: true,
            render: (row) => new Date(row.created_at).toLocaleString(),
          },
          {
            key: 'open',
            label: 'Open',
            render: (row) => <Link href={`/reports/${row.id}`}>View report</Link>,
          },
        ]}
        rows={rows.items}
        filterValue={query}
        onFilterChange={(value) => {
          setQuery(value);
          load(1, value);
        }}
        filterPlaceholder="Search reports..."
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
        emptyMessage="No reports generated yet."
      />
    </div>
  );
}
