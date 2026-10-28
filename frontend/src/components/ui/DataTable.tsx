'use client';

import type { ReactNode } from 'react';

interface DataColumn<T> {
  key: string;
  label: string;
  sortable?: boolean;
  render: (row: T) => ReactNode;
}

interface DataTableProps<T> {
  title: string;
  columns: Array<DataColumn<T>>;
  rows: T[];
  filterValue: string;
  onFilterChange: (value: string) => void;
  filterPlaceholder?: string;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
  onSort: (key: string) => void;
  page: number;
  totalPages: number;
  totalRows: number;
  onPageChange: (page: number) => void;
  emptyMessage: string;
}

export default function DataTable<T>(props: DataTableProps<T>) {
  return (
    <section className="panel table-panel">
      <div className="table-header">
        <h3>{props.title}</h3>
        <div className="table-actions">
          <input
            aria-label={`${props.title} filter`}
            className="table-filter"
            placeholder={props.filterPlaceholder || 'Filter...'}
            value={props.filterValue}
            onChange={(event) => props.onFilterChange(event.target.value)}
          />
        </div>
      </div>

      <div className="table-wrapper">
        <table className="soc-table">
          <thead>
            <tr>
              {props.columns.map((column) => (
                <th key={column.key}>
                  {column.sortable ? (
                    <button
                      type="button"
                      className={`sort-button ${props.sortBy === column.key ? 'active' : ''}`}
                      onClick={() => props.onSort(column.key)}
                    >
                      {column.label}
                      <span>{props.sortBy === column.key ? (props.sortOrder === 'asc' ? '▲' : '▼') : '↕'}</span>
                    </button>
                  ) : (
                    <span>{column.label}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {props.rows.length === 0 && (
              <tr>
                <td colSpan={props.columns.length} className="empty-cell">
                  {props.emptyMessage}
                </td>
              </tr>
            )}
            {props.rows.map((row, index) => (
              <tr key={index}>
                {props.columns.map((column) => (
                  <td key={column.key}>{column.render(row)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="table-pagination">
        <span>
          Page {props.page} / {props.totalPages} · {props.totalRows} rows
        </span>
        <div className="table-pagination-controls">
          <button type="button" onClick={() => props.onPageChange(props.page - 1)} disabled={props.page <= 1}>
            Previous
          </button>
          <button
            type="button"
            onClick={() => props.onPageChange(props.page + 1)}
            disabled={props.page >= props.totalPages}
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
