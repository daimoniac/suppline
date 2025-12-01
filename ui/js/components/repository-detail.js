/**
 * Repository Detail Component
 * Displays all tags within a repository with filtering, sorting, and pagination capabilities.
 */

import { BaseComponent } from './base-component.js';
import { formatDate, formatRelativeTime } from '../utils/date.js';
import { Modal } from './common.js';

export class RepositoryDetail extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.repositoryName = null;
        this.tags = [];
        this.total = 0;
        this.currentPage = 1;
        this.pageSize = 10;
        this.filters = {
            search: '',
        };
        this.sortColumn = 'name';
        this.sortDirection = 'asc';
    }

    /**
     * Load data - implementation of BaseComponent method
     */
    async loadData() {
        if (!this.repositoryName) {
            throw new Error('Repository name not set');
        }
        await this.loadRepository();
    }

    /**
     * Load repository and tags from API with current filters and pagination
     */
    async loadRepository() {
        try {
            const offset = (this.currentPage - 1) * this.pageSize;
            const apiFilters = {
                limit: this.pageSize,
                offset: offset,
            };

            if (this.filters.search) {
                apiFilters.search = this.filters.search;
            }

            // API returns repository with tags
            const response = await this.apiClient.getRepository(this.repositoryName, apiFilters);
            
            // Handle both direct object and object with Tags property (Go returns uppercase)
            if (response && response.Tags) {
                this.tags = Array.isArray(response.Tags) ? response.Tags : [];
                this.total = response.Total || response.Tags.length;
            } else if (response && response.tags) {
                // Fallback for lowercase (in case API changes)
                this.tags = Array.isArray(response.tags) ? response.tags : [];
                this.total = response.total || response.tags.length;
            } else {
                this.tags = [];
                this.total = 0;
            }

            // Apply client-side sorting
            this.sortTags();

            return { tags: this.tags, total: this.total };
        } catch (error) {
            console.error('Failed to load repository:', error);
            throw error;
        }
    }

    /**
     * Set repository name
     */
    setRepository(name) {
        this.repositoryName = name;
    }

    /**
     * Sort tags by current sort column and direction
     */
    sortTags() {
        // Map camelCase column names to PascalCase API property names
        const columnMap = {
            'name': 'Name',
            'lastScanTime': 'LastScanTime',
            'nextScanTime': 'NextScanTime'
        };

        const apiColumn = columnMap[this.sortColumn] || this.sortColumn;

        this.tags.sort((a, b) => {
            let aVal = a[apiColumn];
            let bVal = b[apiColumn];

            // Handle null/undefined values
            if (aVal === null || aVal === undefined) aVal = '';
            if (bVal === null || bVal === undefined) bVal = '';

            // Handle date sorting (Unix timestamps in seconds)
            if (this.sortColumn === 'lastScanTime' || this.sortColumn === 'nextScanTime') {
                // Unix timestamps are already numbers, just ensure they're treated as such
                aVal = typeof aVal === 'number' ? aVal : (new Date(aVal).getTime() / 1000);
                bVal = typeof bVal === 'number' ? bVal : (new Date(bVal).getTime() / 1000);
            }

            // Handle numeric sorting
            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return this.sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
            }

            // Handle string sorting
            const comparison = String(aVal).localeCompare(String(bVal));
            return this.sortDirection === 'asc' ? comparison : -comparison;
        });
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
        this.sortTags();
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
     * Render the complete repository detail view
     */
    render() {
        return `
            <div class="repository-detail">
                <div class="repository-detail-header">
                    <button id="back-btn" class="btn btn-secondary btn-back">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="19" y1="12" x2="5" y2="12"></line>
                            <polyline points="12 19 5 12 12 5"></polyline>
                        </svg>
                        Back
                    </button>
                    <div class="repository-detail-title">
                        <h1 class="page-title">${this.escapeHtml(this.repositoryName)}</h1>
                        <p class="page-subtitle">Repository with ${this.total} tag${this.total !== 1 ? 's' : ''}</p>
                    </div>
                </div>

                ${this.renderFilters()}
                ${this.renderTagsTable()}
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
                    <label for="filter-tag-search">Search Tag</label>
                    <input 
                        type="text" 
                        id="filter-tag-search" 
                        class="filter-input"
                        placeholder="Filter by tag name..."
                        value="${this.escapeHtml(this.filters.search)}"
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
     * Render tags table
     */
    renderTagsTable() {
        if (this.tags.length === 0) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                    <h3>No tags found</h3>
                    <p>Try adjusting your filters or check back later</p>
                </div>
            `;
        }

        return `
            <div class="table-container">
                <table class="tags-table">
                    <thead>
                        <tr>
                            ${this.renderTableHeader('name', 'Tag')}
                            ${this.renderTableHeader('lastScanTime', 'Last Scan')}
                            <th>Vulnerabilities</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.tags.map(tag => this.renderTagRow(tag)).join('')}
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
     * Render individual tag row
     */
    renderTagRow(tag) {
        // Go API returns PascalCase property names
        const statusClass = tag.PolicyPassed ? 'status-success' : 'status-danger';
        const statusText = tag.PolicyPassed ? 'Passed' : 'Failed';
        const lastScanTime = tag.LastScanTime ? formatRelativeTime(tag.LastScanTime) : 'Never';

        const vulnCounts = [
            { severity: 'critical', count: tag.VulnerabilityCount?.Critical || 0 },
            { severity: 'high', count: tag.VulnerabilityCount?.High || 0 },
            { severity: 'medium', count: tag.VulnerabilityCount?.Medium || 0 },
            { severity: 'low', count: tag.VulnerabilityCount?.Low || 0 },
            { severity: 'tolerated', count: tag.VulnerabilityCount?.Tolerated || 0 },
        ];

        const vulnDisplay = vulnCounts
            .map(v => `<span class="vuln-badge vuln-badge-${v.severity}">${v.count}</span>`)
            .join(' ');

        return `
            <tr class="tag-row" data-tag="${this.escapeHtml(tag.Name)}" data-digest="${this.escapeHtml(tag.Digest || '')}">
                <td class="tag-name-cell clickable" data-digest="${this.escapeHtml(tag.Digest || '')}">${this.escapeHtml(tag.Name)}</td>
                <td title="${tag.LastScanTime ? formatDate(tag.LastScanTime) : 'Never scanned'}">${lastScanTime}</td>
                <td class="vulnerabilities-cell">
                    ${vulnDisplay}
                </td>
                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                <td>
                    <button class="btn btn-sm btn-warning rescan-tag-btn" data-tag="${this.escapeHtml(tag.Name)}">
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
                    Showing ${startItem}-${endItem} of ${this.total} tags
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
        if (this.sortColumn !== 'name') {
            queryParams.sort = this.sortColumn;
        }
        if (this.sortDirection !== 'asc') {
            queryParams.order = this.sortDirection;
        }
        
        window.router.navigate(`/repositories/${encodeURIComponent(this.repositoryName)}`, queryParams, true);
    }

    /**
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Back button
        const backBtn = document.getElementById('back-btn');
        if (backBtn) {
            backBtn.addEventListener('click', () => {
                window.router.navigate('/repositories');
            });
        }

        // Filter controls
        const applyFiltersBtn = document.getElementById('apply-filters-btn');
        const clearFiltersBtn = document.getElementById('clear-filters-btn');
        const searchInput = document.getElementById('filter-tag-search');

        if (applyFiltersBtn) {
            applyFiltersBtn.addEventListener('click', async () => {
                const search = searchInput.value.trim();
                this.setFilters({ search });
                this.currentPage = 1;
                this.updateURL();
                await this.loadAndRender();
            });
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', async () => {
                this.setFilters({ search: '' });
                this.currentPage = 1;
                this.updateURL();
                await this.loadAndRender();
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
                this.renderAndAttach();
            });
        });

        // Tag name click handlers - navigate to tag detail view
        document.querySelectorAll('.tag-name-cell').forEach(cell => {
            cell.addEventListener('click', () => {
                const digest = cell.dataset.digest;
                if (digest) {
                    window.router.navigate(`/repositories/${encodeURIComponent(this.repositoryName)}/tags/${encodeURIComponent(digest)}`);
                }
            });
        });

        // Rescan button handlers
        document.querySelectorAll('.rescan-tag-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                const tagName = btn.dataset.tag;
                if (tagName) {
                    await this.handleRescanTag(tagName);
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
                await this.loadAndRender();
            });
        }

        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', async () => {
                this.goToPage(this.currentPage - 1);
                this.updateURL();
                await this.loadAndRender();
            });
        }

        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', async () => {
                this.goToPage(this.currentPage + 1);
                this.updateURL();
                await this.loadAndRender();
            });
        }

        if (lastPageBtn) {
            lastPageBtn.addEventListener('click', async () => {
                const totalPages = Math.ceil(this.total / this.pageSize);
                this.goToPage(totalPages);
                this.updateURL();
                await this.loadAndRender();
            });
        }
    }

    /**
     * Handle tag rescan action
     */
    async handleRescanTag(tagName) {
        if (!tagName || !this.repositoryName) {
            this.showNotification('Missing tag or repository information', 'error');
            return;
        }

        // Show confirmation dialog
        const confirmed = await Modal.confirm(
            'Rescan Tag',
            `Are you sure you want to trigger a rescan for tag "${tagName}" in repository "${this.repositoryName}"?`
        );

        if (!confirmed) {
            return;
        }

        try {
            // Find and disable the button
            const rescanBtn = document.querySelector(`[data-tag="${tagName}"].rescan-tag-btn`);
            if (rescanBtn) {
                rescanBtn.disabled = true;
                rescanBtn.innerHTML = `
                    <span class="spinner-small"></span>
                    Rescanning...
                `;
            }

            // Trigger rescan via API
            const response = await this.apiClient.triggerTagRescan(this.repositoryName, tagName);

            // Show success notification
            const message = response.message || `Tag rescan triggered successfully`;
            this.showNotification(message, 'success');

            // Reload repository after a short delay
            setTimeout(async () => {
                await this.loadAndRender();
            }, 2000);

        } catch (error) {
            console.error('Failed to trigger tag rescan:', error);
            this.showNotification(
                error.message || 'Failed to trigger tag rescan',
                'error'
            );

            // Re-enable button
            const rescanBtn = document.querySelector(`[data-tag="${tagName}"].rescan-tag-btn`);
            if (rescanBtn) {
                rescanBtn.disabled = false;
                rescanBtn.innerHTML = 'Rescan';
            }
        }
    }
}
