import {
  LayoutDashboard, Layers, ScanSearch, ShieldAlert, Bug,
  Plug, ClipboardList, Scale, FolderSync, Skull,
} from 'lucide-react';

export type NavItem = { to: string; icon: typeof LayoutDashboard; label: string; end?: boolean };

const navItems: NavItem[] = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/tasks', icon: ClipboardList, label: 'Housekeeping' },
  { to: '/triage', icon: Scale, label: 'Triage' },
  { to: '/repositories', icon: Layers, label: 'Repositories' },
  { to: '/scans', icon: ScanSearch, label: 'Scans' },
  { to: '/failed', icon: ShieldAlert, label: 'Policy Exceptions' },
  { to: '/vulnerabilities?severity=critical', icon: Bug, label: 'Vulnerabilities' },
  { to: '/integrations', icon: Plug, label: 'Integrations' },
];

/** Optional views join the base list: Malicious Packages after Vulnerabilities, Mirror just above Integrations. */
export function sidebarItems(mirrorEnabled: boolean, maliciousEnabled: boolean): NavItem[] {
  const items: NavItem[] = [];
  for (const item of navItems) {
    if (item.to === '/integrations' && mirrorEnabled) items.push({ to: '/mirror', icon: FolderSync, label: 'Mirror' });
    items.push(item);
    if (item.to.startsWith('/vulnerabilities') && maliciousEnabled) items.push({ to: '/malicious', icon: Skull, label: 'Malicious Packages' });
  }
  return items;
}
