'use client';

import { useCallback, useEffect, useState } from 'react';
import DataTable from '@/components/ui/DataTable';
import { getIOCs } from '@/lib/api';
import { riskClass } from '@/lib/risk';
import type { IOCRecord, PagedResponse } from '@/types';

export default function IndicatorsPage() {
  const [rows, setRows] = useState<PagedResponse<IOCRecord>>({
    items: [],
    total: 0,
    page: 1,
    page_size: 20,
    total_pages: 1,
  });
  const [query, setQuery] = useState('');
  const [iocType, setIocType] = useState('');
  const [severity, setSeverity] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const load = useCallback(
    async (page: number, nextQuery = query, nextSortBy = sortBy, nextSortOrder = sortOrder) => {
      try {
        const payload = await getIOCs({
          page,
          pageSize: 20,
          q: nextQuery,
          type: iocType,
          severity,
          sortBy: nextSortBy,
          sortOrder: nextSortOrder,
        });
        setRows(payload);
      } catch {
        setRows((prev) => ({ ...prev, items: [] }));
      }
    },
    [query, sortBy, sortOrder, iocType, severity]
  );

  useEffect(() => {
    load(1);
  }, [load]);

  return (
    <div className="page-grid">
      <section className="panel page-heading">
        <div>
          <p className="eyebrow">Indicators</p>
          <h1>IOC Management Console</h1>
          <p className="subtitle">Sortable and filterable indicator inventory for SOC analysts.</p>
        </div>
        <div className="filters-inline">
          <select aria-label="Indicator type filter" value={iocType} onChange={(event) => setIocType(event.target.value)}>
            <option value="">All Types</option>
            <option value="URL">URL</option>
            <option value="DOMAIN">DOMAIN</option>
            <option value="IP">IP</option>
            <option value="ISSUER">ISSUER</option>
          </select>
          <select aria-label="Severity filter" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All Severity</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
          <button className="secondary-button" onClick={() => load(1)}>
            Apply
          </button>
        </div>
      </section>

      <DataTable<IOCRecord>
        title="Indicator Table"
        columns={[
          { key: 'indicator', label: 'Indicator', sortable: true, render: (row) => row.indicator },
          { key: 'indicator_type', label: 'Type', sortable: true, render: (row) => row.indicator_type },
          {
            key: 'severity',
            label: 'Severity',
            sortable: true,
            render: (row) => <span className={riskClass(row.severity)}>{row.severity}</span>,
          },
          { key: 'source_check', label: 'Source Check', sortable: true, render: (row) => row.source_check },
          { key: 'country', label: 'Country', sortable: true, render: (row) => row.country || '-' },
          {
            key: 'created_at',
            label: 'Timestamp',
            sortable: true,
            render: (row) => new Date(row.created_at).toLocaleString(),
          },
        ]}
        rows={rows.items}
        filterValue={query}
        onFilterChange={(value) => {
          setQuery(value);
          load(1, value);
        }}
        filterPlaceholder="Search indicators..."
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
        emptyMessage="No indicators available."
      />
    </div>
  );
}
