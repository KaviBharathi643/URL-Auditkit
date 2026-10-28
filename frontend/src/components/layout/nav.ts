export interface NavItem {
  href: string;
  label: string;
}

export const NAV_ITEMS: NavItem[] = [
  { href: '/', label: 'Dashboard' },
  { href: '/scanner', label: 'URL Scanner' },
  { href: '/threat-intelligence', label: 'Threat Intelligence' },
  { href: '/history', label: 'Scan History' },
  { href: '/reports', label: 'Reports' },
  { href: '/indicators', label: 'Indicators' },
  { href: '/settings', label: 'Settings' },
];
