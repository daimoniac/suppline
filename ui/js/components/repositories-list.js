/**
 * Repositories List Component
 * Displays all repositories with filtering, sorting, and pagination capabilities.
 */

import { BaseComponent } from './base-component.js';
import { escapeHtml } from '../utils/security.js';
import { formatDate, formatRelativeTime } from '../utils/date.js';
import { Modal } from './common.js';

export class RepositoriesList extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.repositories = [];
        this.total = 0;
        this.currentPage = 1;
        this.pageSize = 10;
        this.filters = {
            search: '',
        };
        this.sortColumn = 'lastScanTime';
        this.sortDirection = 'desc';
    }

    /**
     * Load data - implementation of BaseComponent method
     */
    async loadData() {
        await this.loadRepositories();
    }

    /**
     * Load repositories from API with current filters and pagination
     */
    async loadRepositories() {
        try {
            const offset = (this.currentPage - 1) * this.pageSize;
            const apiFilters = {
                limit: this.pageSize,
                offset: offset,
                max_age: 86400, // Only show repositories scanned in the last 24 hours (86400 seconds)
            };

            if (this.filters.search) {
                apiFilters.search = this.filters.search;
            }

            // Add server-side sorting
            apiFilters.sort_by = this.getSortByParam();

            // API returns repositories with aggregated data
            const response = await this.apiClient.getRepositories(apiFilters);
            
            // Handle both direct array and object with Repositories property (Go returns uppercase)
            if (Array.isArray(response)) {
                this.repositories = response;
                this.total = response.length;
            } else if (response && Array.isArray(response.Repositories)) {
                this.repositories = response.Repositories;
                this.total = response.Total || response.Repositories.length;
            } else if (response && Array.isArray(response.repositories)) {
                // Fallback for lowercase (in case API changes)
                this.repositories = response.repositories;
                this.total = response.total || response.repositories.length;
            } else {
                this.repositories = [];
                this.total = 0;
            }

            return { repositories: this.repositories, total: this.total };
        } catch (error) {
            console.error('Failed to load repositories:', error);
            throw error;
        }
    }

    /**
     * Get the sort_by parameter for the API based on current sort settings
     */
    getSortByParam() {
        // Map frontend sort columns to API sort_by values
        const sortMap = {
            'name': this.sortDirection === 'asc' ? 'name_asc' : 'name_desc',
            'lastScanTime': this.sortDirection === 'asc' ? 'age_asc' : 'age_desc',
            'status': this.sortDirection === 'asc' ? 'status_asc' : 'status_desc'
        };

        return sortMap[this.sortColumn] || 'age_desc';
    }

    /**
     * Set filter values
     */
    setFilters(filters) {
        this.filters = { ...this.filters, ...filters };
        this.currentPage = 1; // Reset to first page when filters change
    }

    /**
     * Set sort column and direction
     */
    setSort(column, direction = null) {
        if (this.sortColumn === column && direction === null) {
            // Toggle direction if same column
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = direction || 'asc';
        }
        // No need to sort locally - will be handled by API on next load
    }

    /**
     * Go to specific page
     */
    goToPage(page) {
        const totalPages = Math.ceil(this.total / this.pageSize);
        if (page >= 1 && page <= totalPages) {
            this.currentPage = page;
        }
    }

    /**
     * Render the complete repositories list view
     */
    render() {
        return `
            <div class="repositories-list">
                <div class="repositories-header">
                    <h1 class="page-title">Repositories Overview</h1>
                    <p class="page-subtitle">View all repositories and their scanning status</p>
                </div>

                ${this.renderFilters()}
                ${this.renderRepositoriesTable()}
                ${this.renderPagination()}
            </div>
        `;
    }

    /**
     * Render filter controls
     */
    renderFilters() {
        return `
            <div class="filters-container">
                <div class="filter-group">
                    <label for="filter-repository-search">Search Repository</label>
                    <input 
                        type="text" 
                        id="filter-repository-search" 
                        class="filter-input"
                        placeholder="Filter by repository name..."
                        value="${escapeHtml(this.filters.search)}"
                    />
                </div>

                <div class="filter-actions">
                    <button id="apply-filters-btn" class="btn btn-primary">Apply Filters</button>
                    <button id="clear-filters-btn" class="btn btn-secondary">Clear</button>
                </div>
            </div>
        `;
    }

    /**
     * Render repositories table
     */
    renderRepositoriesTable() {
        if (this.repositories.length === 0) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                    <h3>No repositories found</h3>
                    <p>No repositories match your current filters. Try adjusting your search criteria.</p>
                </div>
            `;
        }

        return `
            <div class="table-container">
                <table class="repositories-table">
                    <thead>
                        <tr>
                            ${this.renderTableHeader('name', 'Name')}
                            ${this.renderTableHeader('lastScanTime', 'Last Scan')}
                            <th>Vulnerabilities</th>
                            ${this.renderTableHeader('status', 'Status')}
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.repositories.map(repo => this.renderRepositoryRow(repo)).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    /**
     * Render sortable table header
     */
    renderTableHeader(column, label) {
        const isSorted = this.sortColumn === column;
        const sortIcon = isSorted 
            ? (this.sortDirection === 'asc' ? '↑' : '↓')
            : '';
        const sortClass = isSorted ? 'sorted' : '';

        return `
            <th class="sortable ${sortClass}" data-column="${column}">
                ${label} ${sortIcon}
            </th>
        `;
    }

    /**
     * Render individual repository row
     */
    renderRepositoryRow(repo) {
        // Go API returns PascalCase property names
        const statusClass = repo.PolicyPassed ? 'status-success' : 'status-danger';
        const statusText = repo.PolicyPassed ? 'Passed' : 'Failed';
        const lastScanTime = repo.LastScanTime ? formatRelativeTime(repo.LastScanTime) : 'Never';

        const vulnCounts = [
            { severity: 'critical', count: repo.VulnerabilityCount?.Critical || 0 },
            { severity: 'high', count: repo.VulnerabilityCount?.High || 0 },
            { severity: 'medium', count: repo.VulnerabilityCount?.Medium || 0 },
            { severity: 'low', count: repo.VulnerabilityCount?.Low || 0 },
            { severity: 'tolerated', count: repo.VulnerabilityCount?.Tolerated || 0 },
        ];

        const vulnDisplay = vulnCounts
            .map(v => `<span class="vuln-badge vuln-badge-${v.severity}">${v.count}</span>`)
            .join(' ');

        return `
            <tr class="repository-row" data-repository="${escapeHtml(repo.Name)}">
                <td class="repository-name-cell clickable" data-repository="${escapeHtml(repo.Name)}">${escapeHtml(repo.Name)}</td>
                <td title="${repo.LastScanTime ? formatDate(repo.LastScanTime) : 'Never scanned'}">${lastScanTime}</td>
                <td class="vulnerabilities-cell">
                    ${vulnDisplay}
                </td>
                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                <td>
                    <button class="btn btn-sm btn-warning rescan-repo-btn" data-repository="${escapeHtml(repo.Name)}">
                        Rescan
                    </button>
                </td>
            </tr>
        `;
    }

    /**
     * Render pagination controls
     */
    renderPagination() {
        const totalPages = Math.ceil(this.total / this.pageSize);
        
        if (totalPages <= 1) {
            return '';
        }

        const startItem = (this.currentPage - 1) * this.pageSize + 1;
        const endItem = Math.min(this.currentPage * this.pageSize, this.total);

        return `
            <div class="pagination-container">
                <div class="pagination-info">
                    Showing ${startItem}-${endItem} of ${this.total} repositories
                </div>
                <div class="pagination-controls">
                    <button 
                        class="btn btn-sm" 
                        id="first-page-btn"
                        ${this.currentPage === 1 ? 'disabled' : ''}
                    >
                        First
                    </button>
                    <button 
                        class="btn btn-sm" 
                        id="prev-page-btn"
                        ${this.currentPage === 1 ? 'disabled' : ''}
                    >
                        Previous
                    </button>
                    <span class="pagination-current">
                        Page ${this.currentPage} of ${totalPages}
                    </span>
                    <button 
                        class="btn btn-sm" 
                        id="next-page-btn"
                        ${this.currentPage === totalPages ? 'disabled' : ''}
                    >
                        Next
                    </button>
                    <button 
                        class="btn btn-sm" 
                        id="last-page-btn"
                        ${this.currentPage === totalPages ? 'disabled' : ''}
                    >
                        Last
                    </button>
                </div>
            </div>
        `;
    }

    /**
     * Update URL with current state (filters, sort, pagination)
     */
    updateURL() {
        const queryParams = {};
        
        if (this.filters.search) {
            queryParams.search = this.filters.search;
        }
        if (this.currentPage > 1) {
            queryParams.page = this.currentPage;
        }
        if (this.sortColumn !== 'lastScanTime' || this.sortDirection !== 'desc') {
            queryParams.sort = this.sortColumn;
            queryParams.order = this.sortDirection;
        }
        
        window.router.navigate('/repositories', queryParams, true);
    }

    /**
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Filter controls
        const applyFiltersBtn = document.getElementById('apply-filters-btn');
        const clearFiltersBtn = document.getElementById('clear-filters-btn');
        const searchInput = document.getElementById('filter-repository-search');

        if (applyFiltersBtn) {
            applyFiltersBtn.addEventListener('click', async () => {
                const search = searchInput.value.trim();
                this.setFilters({ search });
                this.currentPage = 1;
                this.updateURL();
                // Don't call loadAndRender() - let the router handle the reload
            });
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', async () => {
                this.setFilters({ search: '' });
                this.currentPage = 1;
                this.updateURL();
                // Don't call loadAndRender() - let the router handle the reload
            });
        }

        // Allow Enter key to apply filters
        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    applyFiltersBtn.click();
                }
            });
        }

        // Sortable column headers
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', async () => {
                const column = header.dataset.column;
                this.setSort(column);
                this.currentPage = 1;
                this.updateURL();
                // Don't call loadAndRender() - let the router handle the reload
            });
        });

        // Repository name click handlers - navigate to detail view
        document.querySelectorAll('.repository-name-cell').forEach(cell => {
            cell.addEventListener('click', () => {
                const repositoryName = cell.dataset.repository;
                if (repositoryName) {
                    window.router.navigate(`/repositories/${encodeURIComponent(repositoryName)}`);
                }
            });
        });

        // Rescan button handlers
        document.querySelectorAll('.rescan-repo-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                const repositoryName = btn.dataset.repository;
                if (repositoryName) {
                    await this.handleRescanRepository(repositoryName);
                }
            });
        });

        // Pagination controls
        const firstPageBtn = document.getElementById('first-page-btn');
        const prevPageBtn = document.getElementById('prev-page-btn');
        const nextPageBtn = document.getElementById('next-page-btn');
        const lastPageBtn = document.getElementById('last-page-btn');

        if (firstPageBtn) {
            firstPageBtn.addEventListener('click', async () => {
                this.goToPage(1);
                this.updateURL();
                // Don't call loadAndRender() - let the router handle the reload
            });
        }

        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', async () => {
                this.goToPage(this.currentPage - 1);
                this.updateURL();
                // Don't call loadAndRender() - let the router handle the reload
            });
        }

        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', async () => {
                this.goToPage(this.currentPage + 1);
                this.updateURL();
                // Don't call loadAndRender() - let the router handle the reload
            });
        }

        if (lastPageBtn) {
            lastPageBtn.addEventListener('click', async () => {
                const totalPages = Math.ceil(this.total / this.pageSize);
                this.goToPage(totalPages);
                this.updateURL();
                // Don't call loadAndRender() - let the router handle the reload
            });
        }
    }

    /**
     * Handle repository rescan action
     */
    async handleRescanRepository(repositoryName) {
        if (!repositoryName) {
            this.showNotification('No repository selected', 'error');
            return;
        }

        // Show confirmation dialog
        const confirmed = await Modal.confirm(
            'Rescan Repository',
            `Are you sure you want to trigger a rescan for all images in repository "${repositoryName}"? This will queue scans for all images in this repository.`
        );

        if (!confirmed) {
            return;
        }

        try {
            // Find and disable the button
            const rescanBtn = document.querySelector(`[data-repository="${repositoryName}"].rescan-repo-btn`);
            if (rescanBtn) {
                rescanBtn.disabled = true;
                rescanBtn.innerHTML = `
                    <span class="spinner-small"></span>
                    Rescanning...
                `;
            }

            // Trigger rescan via API
            const response = await this.apiClient.triggerRepositoryRescan(repositoryName);

            // Show success notification
            const message = response.message || `Repository rescan triggered successfully`;
            this.showNotification(message, 'success');

            // Reload repositories after a short delay
            setTimeout(async () => {
                await this.loadAndRender();
            }, 2000);

        } catch (error) {
            console.error('Failed to trigger repository rescan:', error);
            this.showNotification(
                error.message || 'Failed to trigger repository rescan',
                'error'
            );

            // Re-enable button
            const rescanBtn = document.querySelector(`[data-repository="${repositoryName}"].rescan-repo-btn`);
            if (rescanBtn) {
                rescanBtn.disabled = false;
                rescanBtn.innerHTML = 'Rescan';
            }
        }
    }
}
