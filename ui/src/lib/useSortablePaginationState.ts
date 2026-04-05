import { useState } from 'react';

export type SortDirection = 'asc' | 'desc';

export function useSortablePaginationState({
  initialSortColumn,
  initialSortDirection,
  resolveNewColumnDirection,
  initialPage = 1,
  pageSize,
  totalItems,
}: {
  initialSortColumn: string;
  initialSortDirection: SortDirection;
  resolveNewColumnDirection?: (column: string) => SortDirection;
  initialPage?: number;
  pageSize: number;
  totalItems: number;
}) {
  const [sortColumn, setSortColumn] = useState(initialSortColumn);
  const [sortDirection, setSortDirection] = useState<SortDirection>(initialSortDirection);
  const [rawPage, setRawPage] = useState(Math.max(1, initialPage));
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const page = Math.min(rawPage, totalPages);
  const offset = (page - 1) * pageSize;
  const toggleSort = (column: string) => column === sortColumn
    ? setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    : (setSortColumn(column), setSortDirection(resolveNewColumnDirection?.(column) ?? 'asc'));

  return { sortColumn, sortDirection, toggleSort, page, setPage: (nextPage: number) => setRawPage(Math.max(1, nextPage)), totalPages, offset };
}
