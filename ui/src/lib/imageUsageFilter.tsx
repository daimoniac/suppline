import { createContext, useContext, useEffect, useMemo, useState } from 'react';

export type ImageUsageFilter = 'all' | 'in-use' | 'not-in-use';

interface ImageUsageFilterContextValue {
  filter: ImageUsageFilter;
  setFilter: (next: ImageUsageFilter) => void;
  inUseQuery: boolean | undefined;
}

const STORAGE_KEY = 'suppline:image-usage-filter';

const ImageUsageFilterContext = createContext<ImageUsageFilterContextValue | null>(null);

function isValidFilter(value: string | null): value is ImageUsageFilter {
  return value === 'all' || value === 'in-use' || value === 'not-in-use';
}

function filterToInUseQuery(filter: ImageUsageFilter): boolean | undefined {
  if (filter === 'all') return undefined;
  return filter === 'in-use';
}

export function ImageUsageFilterProvider({ children }: { children: React.ReactNode }) {
  const [filter, setFilter] = useState<ImageUsageFilter>(() => {
    if (typeof window === 'undefined') return 'all';
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isValidFilter(stored) ? stored : 'all';
  });

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, filter);
  }, [filter]);

  const value = useMemo<ImageUsageFilterContextValue>(() => ({
    filter,
    setFilter,
    inUseQuery: filterToInUseQuery(filter),
  }), [filter]);

  return <ImageUsageFilterContext.Provider value={value}>{children}</ImageUsageFilterContext.Provider>;
}

export function useImageUsageFilter() {
  const ctx = useContext(ImageUsageFilterContext);
  if (!ctx) {
    throw new Error('useImageUsageFilter must be used within ImageUsageFilterProvider');
  }
  return ctx;
}