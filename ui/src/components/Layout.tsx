import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import {
  LayoutDashboard, Layers, ScanSearch, ShieldAlert, Bug, FileWarning,
  Plug, LogOut,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/repositories', icon: Layers, label: 'Repositories' },
  { to: '/scans', icon: ScanSearch, label: 'Scans' },
  { to: '/failed', icon: ShieldAlert, label: 'Failed Images' },
  { to: '/vulnerabilities?severity=critical', icon: Bug, label: 'Vulnerabilities' },
  { to: '/tolerations', icon: FileWarning, label: 'Tolerations' },
  { to: '/integrations', icon: Plug, label: 'Integrations' },
];

export default function Layout() {
  const { logout } = useAuth();

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-bg-primary border-r border-border flex flex-col">
        {/* Logo */}
        <div className="h-14 flex items-center gap-2.5 px-4 border-b border-border">
          <div className="w-7 h-7 bg-accent rounded-lg flex items-center justify-center">
            <span className="text-bg-primary font-bold text-sm">S</span>
          </div>
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
