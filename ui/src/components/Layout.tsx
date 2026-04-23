import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import {
  LayoutDashboard, Layers, ScanSearch, ShieldAlert, Bug, ShieldCheck,
  Plug, LogOut, ClipboardList, Menu, X,
} from 'lucide-react';
import { ImageUsageFilterProvider, useImageUsageFilter } from '../lib/imageUsageFilter';
import supplineIcon from '../assets/suppline-icon.svg';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/tasks', icon: ClipboardList, label: 'Tasks' },
  { to: '/repositories', icon: Layers, label: 'Repositories' },
  { to: '/scans', icon: ScanSearch, label: 'Scans' },
  { to: '/failed', icon: ShieldAlert, label: 'Policy Exceptions' },
  { to: '/vulnerabilities?severity=critical', icon: Bug, label: 'Vulnerabilities' },
  { to: '/vex', icon: ShieldCheck, label: 'VEX Statements' },
  { to: '/integrations', icon: Plug, label: 'Integrations' },
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
  const [isCompact, setIsCompact] = useState(() => window.matchMedia('(max-width: 1023px)').matches);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(max-width: 1023px)');

    const handleViewportChange = (event: MediaQueryListEvent) => {
      setIsCompact(event.matches);
      if (!event.matches) {
        setMenuOpen(false);
      }
    };

    mediaQuery.addEventListener('change', handleViewportChange);
    return () => mediaQuery.removeEventListener('change', handleViewportChange);
  }, []);

  useEffect(() => {
    if (!isCompact || !menuOpen) {
      return;
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isCompact, menuOpen]);

  const closeMenuOnCompact = () => {
    if (isCompact) {
      setMenuOpen(false);
    }
  };

  const sidebarVisible = !isCompact || menuOpen;

  return (
    <div className="relative flex h-screen overflow-hidden">
      {isCompact && !menuOpen && (
        <button
          type="button"
          onClick={() => setMenuOpen(true)}
          aria-label="Open navigation menu"
          className="fixed top-3 left-3 z-40 inline-flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-bg-secondary/95 text-text-primary shadow-lg backdrop-blur-sm transition-colors hover:border-border-hover"
        >
          <Menu className="h-5 w-5" />
        </button>
      )}

      {isCompact && menuOpen && (
        <button
          type="button"
          aria-label="Close navigation menu"
          className="fixed inset-0 z-30 bg-black/50"
          onClick={() => setMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`bg-bg-primary border-r border-border flex flex-col z-40 transition-transform duration-200 ease-out ${
          isCompact
            ? `fixed inset-y-0 left-0 w-64 max-w-[85vw] shadow-xl ${sidebarVisible ? 'translate-x-0' : '-translate-x-full'}`
            : 'w-56 flex-shrink-0'
        }`}
      >
        {/* Logo */}
        <div className="h-14 flex items-center border-b border-border">
          <Link
            to="/"
            onClick={closeMenuOnCompact}
            className="flex h-full flex-1 items-center gap-2.5 px-4 hover:bg-bg-tertiary transition-colors"
          >
            <img src={supplineIcon} alt="suppline" className="w-7 h-7" />
            <span className="font-semibold text-sm tracking-tight">suppline</span>
          </Link>
          {isCompact && (
            <button
              type="button"
              onClick={() => setMenuOpen(false)}
              aria-label="Close navigation menu"
              className="mx-2 inline-flex h-9 w-9 items-center justify-center rounded-lg text-text-secondary transition-colors hover:bg-bg-tertiary hover:text-text-primary"
            >
              <X className="h-5 w-5" />
            </button>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={closeMenuOnCompact}
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
              onChange={e => setFilter(e.target.value as 'all' | 'in-use' | 'in-use-newer' | 'not-in-use')}
              className="w-full px-2.5 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50 transition-colors"
            >
              <option value="all">All images</option>
              <option value="in-use">In use</option>
              <option value="in-use-newer">In use + newer</option>
              <option value="not-in-use">Not in use</option>
            </select>
          </div>
        </nav>

        {/* Logout */}
        <div className="p-2 border-t border-border">
          <button
            onClick={() => {
              closeMenuOnCompact();
              logout();
            }}
            className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-text-secondary hover:text-danger hover:bg-danger-bg w-full transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto bg-surface min-w-0">
        <div className={`max-w-7xl mx-auto p-6 ${isCompact ? 'pt-16' : ''}`}>
          <Outlet />
        </div>
      </main>
    </div>
  );
}
