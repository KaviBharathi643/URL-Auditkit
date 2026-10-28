'use client';

import { useEffect, useMemo, useState } from 'react';
import DataTable from '@/components/ui/DataTable';
import { getIOCs, getThreatDomains, getThreatIpReputation, getThreatMap } from '@/lib/api';
import { riskClass } from '@/lib/risk';
import type { IOCRecord, ThreatMapPoint } from '@/types';

interface DomainRow {
  domain: string;
  hits: number;
  last_seen: string;
}

interface IpRow {
  ip: string;
  sightings: number;
  critical_hits: number;
  high_hits: number;
  medium_hits: number;
  last_seen: string;
}

function toMapPosition(point: ThreatMapPoint): { left: string; top: string } {
  const left = ((point.lng + 180) / 360) * 100;
  const top = ((90 - point.lat) / 180) * 100;
  return { left: `${left}%`, top: `${top}%` };
}

function slicePage<T>(rows: T[], page: number, pageSize: number): { items: T[]; totalPages: number } {
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const start = (page - 1) * pageSize;
  return {
    items: rows.slice(start, start + pageSize),
    totalPages,
  };
}

export default function ThreatIntelligencePage() {
  const [mapPoints, setMapPoints] = useState<ThreatMapPoint[]>([]);
  const [domains, setDomains] = useState<DomainRow[]>([]);
  const [ips, setIps] = useState<IpRow[]>([]);
  const [iocRows, setIocRows] = useState<IOCRecord[]>([]);

  const [domainPage, setDomainPage] = useState(1);
  const [domainQuery, setDomainQuery] = useState('');
  const [domainSortBy, setDomainSortBy] = useState<'domain' | 'hits' | 'last_seen'>('hits');
  const [domainSortOrder, setDomainSortOrder] = useState<'asc' | 'desc'>('desc');

  const [ipPage, setIpPage] = useState(1);
  const [ipQuery, setIpQuery] = useState('');
  const [ipSortBy, setIpSortBy] = useState<'ip' | 'sightings' | 'critical_hits' | 'last_seen'>('critical_hits');
  const [ipSortOrder, setIpSortOrder] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    getThreatMap('7d')
      .then((payload) => setMapPoints(payload.points || []))
      .catch(() => setMapPoints([]));
    getThreatDomains(100)
      .then((payload) => setDomains(payload.items || []))
      .catch(() => setDomains([]));
    getThreatIpReputation(100)
      .then((payload) => setIps(payload.items || []))
      .catch(() => setIps([]));
    getIOCs({
      page: 1,
      pageSize: 10,
      q: '',
      type: '',
      severity: '',
      sortBy: 'created_at',
      sortOrder: 'desc',
    })
      .then((payload) => setIocRows(payload.items || []))
      .catch(() => setIocRows([]));
  }, []);

  const domainRows = useMemo(() => {
    const filtered = domains.filter((row) => row.domain.toLowerCase().includes(domainQuery.toLowerCase()));
    const sorted = [...filtered].sort((a, b) => {
      const aVal = a[domainSortBy];
      const bVal = b[domainSortBy];
      if (aVal < bVal) return domainSortOrder === 'asc' ? -1 : 1;
      if (aVal > bVal) return domainSortOrder === 'asc' ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [domains, domainQuery, domainSortBy, domainSortOrder]);

  const ipRows = useMemo(() => {
    const filtered = ips.filter((row) => row.ip.toLowerCase().includes(ipQuery.toLowerCase()));
    const sorted = [...filtered].sort((a, b) => {
      const aVal = a[ipSortBy];
      const bVal = b[ipSortBy];
      if (aVal < bVal) return ipSortOrder === 'asc' ? -1 : 1;
      if (aVal > bVal) return ipSortOrder === 'asc' ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [ips, ipQuery, ipSortBy, ipSortOrder]);

  const domainPageSlice = slicePage(domainRows, domainPage, 8);
  const ipPageSlice = slicePage(ipRows, ipPage, 8);

  return (
    <div className="page-grid">
      <section className="panel page-heading">
        <div>
          <p className="eyebrow">Threat Intelligence</p>
          <h1>Global Threat Correlation</h1>
          <p className="subtitle">Domain, IP, and IOC telemetry mapped for analyst triage and investigations.</p>
        </div>
      </section>

      <section className="panel threat-map-panel">
        <h2>Global Threat Map</h2>
        <div className="world-map">
          <img src="/visuals/world-map.svg" alt="World map" />
          {mapPoints.map((point) => {
            const position = toMapPosition(point);
            const size = Math.min(22, 6 + point.count * 1.5);
            return (
              <span
                key={`${point.country}-${point.lat}-${point.lng}`}
                className="map-marker"
                style={{ ...position, width: size, height: size }}
                title={`${point.country} · ${point.count} indicators`}
              />
            );
          })}
        </div>
      </section>

      <DataTable<DomainRow>
        title="Malicious Domain List"
        columns={[
          { key: 'domain', label: 'Domain', sortable: true, render: (row) => row.domain },
          { key: 'hits', label: 'Hits', sortable: true, render: (row) => row.hits },
          {
            key: 'last_seen',
            label: 'Last Seen',
            sortable: true,
            render: (row) => new Date(row.last_seen).toLocaleString(),
          },
        ]}
        rows={domainPageSlice.items}
        filterValue={domainQuery}
        onFilterChange={(value) => {
          setDomainQuery(value);
          setDomainPage(1);
        }}
        filterPlaceholder="Filter domains..."
        sortBy={domainSortBy}
        sortOrder={domainSortOrder}
        onSort={(key) => {
          const castKey = key as typeof domainSortBy;
          const next = domainSortBy === castKey && domainSortOrder === 'desc' ? 'asc' : 'desc';
          setDomainSortBy(castKey);
          setDomainSortOrder(next);
        }}
        page={domainPage}
        totalPages={domainPageSlice.totalPages}
        totalRows={domainRows.length}
        onPageChange={(page) => setDomainPage(Math.max(1, page))}
        emptyMessage="No malicious domains found."
      />

      <DataTable<IpRow>
        title="IP Reputation Table"
        columns={[
          { key: 'ip', label: 'IP', sortable: true, render: (row) => row.ip },
          { key: 'sightings', label: 'Sightings', sortable: true, render: (row) => row.sightings },
          {
            key: 'critical_hits',
            label: 'Critical Hits',
            sortable: true,
            render: (row) => <span className="risk-badge risk-critical">{row.critical_hits}</span>,
          },
          {
            key: 'high_hits',
            label: 'High Hits',
            sortable: true,
            render: (row) => <span className="risk-badge risk-high">{row.high_hits}</span>,
          },
          {
            key: 'last_seen',
            label: 'Last Seen',
            sortable: true,
            render: (row) => new Date(row.last_seen).toLocaleString(),
          },
        ]}
        rows={ipPageSlice.items}
        filterValue={ipQuery}
        onFilterChange={(value) => {
          setIpQuery(value);
          setIpPage(1);
        }}
        filterPlaceholder="Filter IPs..."
        sortBy={ipSortBy}
        sortOrder={ipSortOrder}
        onSort={(key) => {
          const castKey = key as typeof ipSortBy;
          const next = ipSortBy === castKey && ipSortOrder === 'desc' ? 'asc' : 'desc';
          setIpSortBy(castKey);
          setIpSortOrder(next);
        }}
        page={ipPage}
        totalPages={ipPageSlice.totalPages}
        totalRows={ipRows.length}
        onPageChange={(page) => setIpPage(Math.max(1, page))}
        emptyMessage="No suspicious IP indicators found."
      />

      <section className="panel">
        <h2>Live Indicator Stream</h2>
        <div className="indicator-list">
          {iocRows.map((ioc) => (
            <article key={ioc.id} className="indicator-item">
              <div>
                <strong>{ioc.indicator}</strong>
                <p>
                  {ioc.indicator_type} · {ioc.source_check}
                </p>
              </div>
              <span className={riskClass(ioc.severity)}>{ioc.severity}</span>
            </article>
          ))}
          {iocRows.length === 0 && <p>No live indicators available.</p>}
        </div>
      </section>
    </div>
  );
}
