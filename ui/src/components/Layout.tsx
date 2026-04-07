import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import {
  LayoutDashboard, Layers, ScanSearch, ShieldAlert, Bug, ShieldCheck,
  Plug, LogOut, ClipboardList,
} from 'lucide-react';
import { ImageUsageFilterProvider, useImageUsageFilter } from '../lib/imageUsageFilter';
import supplineIcon from '../assets/suppline-icon.svg';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/repositories', icon: Layers, label: 'Repositories' },
  { to: '/scans', icon: ScanSearch, label: 'Scans' },
  { to: '/failed', icon: ShieldAlert, label: 'Policy Exceptions' },
  { to: '/vulnerabilities?severity=critical', icon: Bug, label: 'Vulnerabilities' },
  { to: '/vex', icon: ShieldCheck, label: 'VEX Statements' },
  { to: '/integrations', icon: Plug, label: 'Integrations' },
  { to: '/tasks', icon: ClipboardList, label: 'Tasks' },
];

export default function Layout() {
  return (
    <ImageUsageFilterProvider>
      <LayoutContent />
    </ImageUsageFilterProvider>
  );
}

function LayoutContent() {
  const { logout } = useAuth();
  const { filter, setFilter } = useImageUsageFilter();

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-bg-primary border-r border-border flex flex-col">
        {/* Logo */}
        <div className="h-14 flex items-center gap-2.5 px-4 border-b border-border">
          <img src={supplineIcon} alt="suppline" className="w-7 h-7" />
          <span className="font-semibold text-sm tracking-tight">suppline</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-accent/10 text-accent font-medium'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary'
                }`
              }
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </NavLink>
          ))}

          <div className="mt-4 px-2">
            <label htmlFor="global-image-usage-filter" className="block text-[11px] font-medium uppercase tracking-wide text-text-muted mb-1.5">
              Image Usage
            </label>
            <select
              id="global-image-usage-filter"
              value={filter}
              onChange={e => setFilter(e.target.value as 'all' | 'in-use' | 'not-in-use')}
              className="w-full px-2.5 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors"
            >
              <option value="all">All images</option>
              <option value="in-use">In use</option>
              <option value="not-in-use">Not in use</option>
            </select>
          </div>
        </nav>

        {/* Logout */}
        <div className="p-2 border-t border-border">
          <button
            onClick={logout}
            className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-text-secondary hover:text-danger hover:bg-danger-bg w-full transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto bg-surface">
        <div className="max-w-7xl mx-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
