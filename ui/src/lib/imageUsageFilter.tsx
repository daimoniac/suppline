import { createContext, useContext, useEffect, useMemo, useState } from 'react';

export type ImageUsageFilter = 'all' | 'in-use' | 'in-use-newer' | 'not-in-use';

interface ImageUsageFilterContextValue {
  filter: ImageUsageFilter;
  setFilter: (next: ImageUsageFilter) => void;
  /**
   * Query params for API requests (e.g. in_use_mode). Undefined when the filter is "all".
   * Prefer this over the legacy in_use boolean.
   */
  inUseRequestParams: Record<string, string> | undefined;
}

const STORAGE_KEY = 'suppline:image-usage-filter';

const ImageUsageFilterContext = createContext<ImageUsageFilterContextValue | null>(null);

function isValidFilter(value: string | null): value is ImageUsageFilter {
  return value === 'all' || value === 'in-use' || value === 'in-use-newer' || value === 'not-in-use';
}

/**
 * Maps global image usage filter to query parameters understood by
 * /api/v1 (see parseListImageUsage in the API). Omits params when "all".
 */
export function imageUsageToRequestParams(filter: ImageUsageFilter): Record<string, string> | undefined {
  switch (filter) {
    case 'all':
      return undefined;
    case 'in-use':
      return { in_use_mode: 'in_use' };
    case 'in-use-newer':
      return { in_use_mode: 'in_use_newer' };
    case 'not-in-use':
      return { in_use_mode: 'not_in_use' };
    default:
      return undefined;
  }
}

export function ImageUsageFilterProvider({ children }: { children: React.ReactNode }) {
  const [filter, setFilter] = useState<ImageUsageFilter>(() => {
    if (typeof window === 'undefined') return 'in-use-newer';
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isValidFilter(stored) ? stored : 'in-use-newer';
  });

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, filter);
  }, [filter]);

  const value = useMemo<ImageUsageFilterContextValue>(() => ({
    filter,
    setFilter,
    inUseRequestParams: imageUsageToRequestParams(filter),
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
