import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;
type PageSize = (typeof PAGE_SIZE_OPTIONS)[number];
const DEFAULT_PAGE_SIZE: PageSize = 25;

interface PageSizePreferenceContextValue {
  pageSize: PageSize;
  setPageSize: (next: number) => void;
  options: readonly PageSize[];
}

const STORAGE_KEY = 'suppline:page-size';

const PageSizePreferenceContext = createContext<PageSizePreferenceContextValue | null>(null);

function isValidPageSize(value: number): value is PageSize {
  return (PAGE_SIZE_OPTIONS as readonly number[]).includes(value);
}

function parseStoredPageSize(value: string | null): PageSize {
  if (value === null) return DEFAULT_PAGE_SIZE;
  const n = Number(value);
  return isValidPageSize(n) ? n : DEFAULT_PAGE_SIZE;
}

export function PageSizePreferenceProvider({ children }: { children: React.ReactNode }) {
  const [pageSize, setPageSizeState] = useState<PageSize>(() => {
    if (typeof window === 'undefined') return DEFAULT_PAGE_SIZE;
    return parseStoredPageSize(window.localStorage.getItem(STORAGE_KEY));
  });

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, String(pageSize));
  }, [pageSize]);

  const setPageSize = useCallback((next: number) => {
    if (isValidPageSize(next)) setPageSizeState(next);
  }, []);

  const value = useMemo<PageSizePreferenceContextValue>(() => ({
    pageSize,
    setPageSize,
    options: PAGE_SIZE_OPTIONS,
  }), [pageSize, setPageSize]);

  return <PageSizePreferenceContext.Provider value={value}>{children}</PageSizePreferenceContext.Provider>;
}

export function usePageSizePreference() {
  const ctx = useContext(PageSizePreferenceContext);
  if (!ctx) {
    throw new Error('usePageSizePreference must be used within PageSizePreferenceProvider');
  }
  return ctx;
}
