'use client';

import DashboardRoundedIcon from '@mui/icons-material/DashboardRounded';
import DescriptionRoundedIcon from '@mui/icons-material/DescriptionRounded';
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded';
import HubRoundedIcon from '@mui/icons-material/HubRounded';
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded';
import TravelExploreRoundedIcon from '@mui/icons-material/TravelExploreRounded';
import TripOriginRoundedIcon from '@mui/icons-material/TripOriginRounded';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { NAV_ITEMS } from './nav';

interface SidebarProps {
  open: boolean;
  onNavigate: () => void;
}

const NAV_ICON_MAP: Record<string, React.ReactNode> = {
  '/': <DashboardRoundedIcon fontSize="small" />,
  '/scanner': <TravelExploreRoundedIcon fontSize="small" />,
  '/threat-intelligence': <HubRoundedIcon fontSize="small" />,
  '/history': <HistoryRoundedIcon fontSize="small" />,
  '/reports': <DescriptionRoundedIcon fontSize="small" />,
  '/indicators': <TripOriginRoundedIcon fontSize="small" />,
  '/settings': <SettingsRoundedIcon fontSize="small" />,
};

export default function Sidebar({ open, onNavigate }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside className={`soc-sidebar ${open ? 'open' : ''}`} aria-label="SOC navigation">
      <div className="sidebar-header">
        <p className="sidebar-kicker">Command Center</p>
        <h2>Navigation</h2>
      </div>

      <div className="sidebar-status panel-glass">
        <span className="live-dot" aria-hidden />
        <div>
          <div className="status-title">Systems Operational</div>
          <div className="status-subtitle">API · Scanner · Threat Intel</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <p className="sidebar-section-label">Workflows</p>
        {NAV_ITEMS.map((item) => {
          const active = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`nav-item ${active ? 'active' : ''}`}
              onClick={onNavigate}
            >
              <span className="nav-icon" aria-hidden>
                {NAV_ICON_MAP[item.href]}
              </span>
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="sidebar-footer panel-glass">
        <div className="sidebar-foot-row">
          <span>Build</span>
          <strong>v3.0 SOC</strong>
        </div>
        <div className="sidebar-foot-row">
          <span>Checks</span>
          <strong>Dynamic (15)</strong>
        </div>
      </div>
    </aside>
  );
}
