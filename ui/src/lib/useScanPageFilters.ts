import { useCallback, useState } from 'react';
import type { SetURLSearchParams } from 'react-router-dom';

interface UseScanPageFiltersOptions {
  initialRepository: string;
  initialPolicyFilter: string;
  policyParamName?: string;
  searchParamName?: string;
  sortColumn: string;
  sortDirection: 'asc' | 'desc';
  defaultSortColumn: string;
  defaultSortDirection: 'asc' | 'desc';
  setPage: (nextPage: number) => void;
  setSearchParams: SetURLSearchParams;
}

export function useScanPageFilters({
  initialRepository,
  initialPolicyFilter,
  policyParamName = 'policy_status',
  searchParamName = 'repository',
  sortColumn,
  sortDirection,
  defaultSortColumn,
  defaultSortDirection,
  setPage,
  setSearchParams,
}: UseScanPageFiltersOptions) {
  const [repositoryInput, setRepositoryInput] = useState(initialRepository);
  const [repository, setRepository] = useState(initialRepository);
  const [policyFilter, setPolicyFilter] = useState(initialPolicyFilter || 'all');

  const updateURL = useCallback((
    nextRepository: string,
    nextPage: number,
    nextPolicyFilter: string,
    nextSortColumn: string,
    nextSortDirection: 'asc' | 'desc',
  ) => {
    const params: Record<string, string> = {};
    if (nextRepository) params[searchParamName] = nextRepository;
    if (nextPage > 1) params.page = String(nextPage);
    if (nextSortColumn !== defaultSortColumn || nextSortDirection !== defaultSortDirection) {
      params.sort = nextSortColumn;
      params.order = nextSortDirection;
    }
    if (nextPolicyFilter && nextPolicyFilter !== 'all') params[policyParamName] = nextPolicyFilter;
    setSearchParams(params, { replace: true });
  }, [defaultSortColumn, defaultSortDirection, policyParamName, searchParamName, setSearchParams]);

  const handleRepositoryInputChange = useCallback((nextRepository: string) => {
    setRepositoryInput(nextRepository);
    setRepository(nextRepository);
    setPage(1);
    updateURL(nextRepository, 1, policyFilter, sortColumn, sortDirection);
  }, [policyFilter, setPage, sortColumn, sortDirection, updateURL]);

  const applyRepositoryFilter = useCallback(() => {
    const trimmed = repositoryInput.trim();
    setRepository(trimmed);
    setRepositoryInput(trimmed);
    setPage(1);
    updateURL(trimmed, 1, policyFilter, sortColumn, sortDirection);
  }, [policyFilter, repositoryInput, setPage, sortColumn, sortDirection, updateURL]);

  const handlePolicyFilterChange = useCallback((nextPolicyFilter: string) => {
    setPolicyFilter(nextPolicyFilter);
    setPage(1);
    updateURL(repository, 1, nextPolicyFilter, sortColumn, sortDirection);
  }, [repository, setPage, sortColumn, sortDirection, updateURL]);

  const clearFilters = useCallback(() => {
    setRepositoryInput('');
    setRepository('');
    setPolicyFilter('all');
    setPage(1);
    updateURL('', 1, 'all', sortColumn, sortDirection);
  }, [setPage, sortColumn, sortDirection, updateURL]);

  const handlePageChange = useCallback((nextPage: number) => {
    setPage(nextPage);
    updateURL(repository, nextPage, policyFilter, sortColumn, sortDirection);
  }, [policyFilter, repository, setPage, sortColumn, sortDirection, updateURL]);

  const handleSortChange = useCallback((nextSortColumn: string, nextSortDirection: 'asc' | 'desc') => {
    setPage(1);
    updateURL(repository, 1, policyFilter, nextSortColumn, nextSortDirection);
  }, [policyFilter, repository, setPage, updateURL]);

  return {
    repositoryInput,
    repository,
    policyFilter,
    handleRepositoryInputChange,
    applyRepositoryFilter,
    handlePolicyFilterChange,
    clearFilters,
    handlePageChange,
    handleSortChange,
  };
}