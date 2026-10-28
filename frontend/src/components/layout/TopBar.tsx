'use client';

import KeyboardCommandKeyRoundedIcon from '@mui/icons-material/KeyboardCommandKeyRounded';
import MenuRoundedIcon from '@mui/icons-material/MenuRounded';
import NotificationsNoneRoundedIcon from '@mui/icons-material/NotificationsNoneRounded';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import ShieldRoundedIcon from '@mui/icons-material/ShieldRounded';

interface TopBarProps {
  onMenuToggle: () => void;
}

export default function TopBar({ onMenuToggle }: TopBarProps) {
  return (
    <header className="soc-topbar">
      <div className="topbar-left">
        <button className="menu-button" onClick={onMenuToggle} aria-label="Toggle navigation">
          <MenuRoundedIcon fontSize="small" />
        </button>

        <div className="brand-group">
          <div className="brand-logo" aria-hidden>
            <ShieldRoundedIcon fontSize="small" />
          </div>
          <div>
            <div className="brand-title">URL Audit Kit</div>
            <div className="brand-subtitle">Security Operations Console</div>
          </div>
        </div>
      </div>

      <label className="topbar-search">
        <SearchRoundedIcon className="search-icon" fontSize="small" />
        <input placeholder="Search URLs, IOCs, reports..." aria-label="Global search" />
        <span className="search-shortcut" aria-hidden>
          <KeyboardCommandKeyRoundedIcon fontSize="inherit" />
          K
        </span>
      </label>

      <div className="topbar-right">
        <div className="live-pill">
          <span className="live-dot" aria-hidden />
          <span className="live-label">Live Telemetry</span>
        </div>
        <button className="icon-button topbar-alert" aria-label="Notifications">
          <NotificationsNoneRoundedIcon fontSize="small" />
          <span className="alert-count" aria-hidden>
            3
          </span>
        </button>
        <button className="profile-pill" aria-label="User menu">
          <span className="avatar">SA</span>
          <span className="profile-meta">
            <strong>SOC Analyst</strong>
            <small>Tier-2 Operator</small>
          </span>
        </button>
      </div>
    </header>
  );
}
