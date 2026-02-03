/**
 * Scans List Component
 * Displays all scans with filtering, sorting, and pagination capabilities.
 */

import { BaseComponent } from './base-component.js';
import { escapeHtml } from '../utils/security.js';
import { formatDate, formatRelativeTime } from '../utils/date.js';
import { truncateDigest } from '../utils/severity.js';
import { Modal } from './common.js';

export class ScansList extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.scans = [];
        this.total = 0;
        this.currentPage = 1;
        this.pageSize = 50;
        this.filters = {
            repository: '',
            policy_passed: null, // null = all, true = passed, false = failed
        };
        this.sortColumn = 'scanned_at';
        this.sortDirection = 'desc';
    }

    /**
     * Load data - implementation of BaseComponent method
     */
    async loadData() {
        await this.loadScans();
    }

    /**
     * Load scans from API with current filters and pagination
     */
    async loadScans() {
        try {
            const offset = (this.currentPage - 1) * this.pageSize;
            const apiFilters = {
                limit: this.pageSize,
                offset: offset,
            };

            if (this.filters.repository) {
                apiFilters.repository = this.filters.repository;
            }

            if (this.filters.policy_passed !== null) {
                apiFilters.policy_passed = this.filters.policy_passed;
            }

            // API returns array directly
            const scans = await this.apiClient.getScans(apiFilters);
            this.scans = Array.isArray(scans) ? scans : [];
            this.total = this.scans.length;

            // Apply client-side sorting
            this.sortScans();

            return { scans: this.scans, total: this.total };
        } catch (error) {
            console.error('Failed to load scans:', error);
            throw error;
        }
    }

    /**
     * Sort scans by current sort column and direction
     */
    sortScans() {
        // Map snake_case column names to PascalCase API field names
        const columnMap = {
            'scanned_at': 'ScannedAt',
            'policy_passed': 'PolicyPassed',
            'repository': 'Repository',
            'tag': 'Tag',
            'digest': 'Digest'
        };

        const apiColumn = columnMap[this.sortColumn] || this.sortColumn;

        this.scans.sort((a, b) => {
            let aVal = a[apiColumn];
            let bVal = b[apiColumn];

            // Handle null/undefined values
            if (aVal === null || aVal === undefined) aVal = '';
            if (bVal === null || bVal === undefined) bVal = '';

            // Handle date sorting (Unix timestamps in seconds)
            if (this.sortColumn === 'scanned_at') {
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
            this.sortDirection = direction || 'desc';
        }
        this.sortScans();
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
     * Render the complete scans list view
     */
    render() {
        return `
            <div class="scans-list">
                <div class="scans-header">
                    <h1 class="page-title">Image Scans</h1>
                    <p class="page-subtitle">View and manage container image security scans</p>
                </div>

                ${this.renderFilters()}
                ${this.renderRescanButton()}
                ${this.renderScansTable()}
                ${this.renderPagination()}
            </div>
        `;
    }

    /**
     * Render filter controls
     */
    renderFilters() {
        const policyPassedValue = this.filters.policy_passed === null ? 'all' : 
                                   this.filters.policy_passed ? 'passed' : 'failed';

        return `
            <div class="filters-container">
                <div class="filter-group">
                    <label for="filter-repository">Repository</label>
                    <input 
                        type="text" 
                        id="filter-repository" 
                        class="filter-input"
                        placeholder="Filter by repository name..."
                        value="${escapeHtml(this.filters.repository)}"
                    />
                </div>

                <div class="filter-group">
                    <label for="filter-policy-status">Policy Status</label>
                    <select id="filter-policy-status" class="filter-select">
                        <option value="all" ${policyPassedValue === 'all' ? 'selected' : ''}>All</option>
                        <option value="passed" ${policyPassedValue === 'passed' ? 'selected' : ''}>Passed</option>
                        <option value="failed" ${policyPassedValue === 'failed' ? 'selected' : ''}>Failed</option>
                    </select>
                </div>

                <div class="filter-actions">
                    <button id="apply-filters-btn" class="btn btn-primary">Apply Filters</button>
                    <button id="clear-filters-btn" class="btn btn-secondary">Clear</button>
                </div>
            </div>
        `;
    }

    /**
     * Render rescan repository button (only when filtered by repository)
     */
    renderRescanButton() {
        if (!this.filters.repository) {
            return '';
        }

        return `
            <div class="rescan-container">
                <button id="rescan-repository-btn" class="btn btn-warning">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                    </svg>
                    Rescan Repository: ${escapeHtml(this.filters.repository)}
                </button>
            </div>
        `;
    }

    /**
     * Render scans table
     */
    renderScansTable() {
        if (this.scans.length === 0) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                    <h3>No scans found</h3>
                    <p>Try adjusting your filters or check back later</p>
                </div>
            `;
        }

        return `
            <div class="table-container">
                <table class="scans-table">
                    <thead>
                        <tr>
                            ${this.renderTableHeader('repository', 'Repository')}
                            ${this.renderTableHeader('tag', 'Tag')}
                            ${this.renderTableHeader('digest', 'Digest')}
                            ${this.renderTableHeader('scanned_at', 'Scanned')}
                            ${this.renderTableHeader('policy_passed', 'Status')}
                            <th>Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.scans.map(scan => this.renderScanRow(scan)).join('')}
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
     * Render individual scan row
     */
    renderScanRow(scan) {
        const statusClass = scan.PolicyPassed ? 'status-success' : 'status-danger';
        const statusText = scan.PolicyPassed ? 'Passed' : 'Failed';
        const truncatedDigest = truncateDigest(scan.Digest);
        const scanTime = formatRelativeTime(scan.CreatedAt);

        const vulnCounts = [
            { severity: 'critical', count: scan.CriticalVulnCount || 0 },
            { severity: 'high', count: scan.HighVulnCount || 0 },
            { severity: 'medium', count: scan.MediumVulnCount || 0 },
            { severity: 'low', count: scan.LowVulnCount || 0 }
        ].filter(v => v.count > 0);

        return `
            <tr class="scan-row clickable" data-digest="${escapeHtml(scan.Digest)}">
                <td>${escapeHtml(scan.Repository || 'N/A')}</td>
                <td>${escapeHtml(scan.Tag || 'N/A')}</td>
                <td class="digest-cell" title="${escapeHtml(scan.Digest)}">${escapeHtml(truncatedDigest)}</td>
                <td title="${formatDate(scan.CreatedAt)}">${scanTime}</td>
                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                <td class="vulnerabilities-cell">
                    ${vulnCounts.length > 0 
                        ? vulnCounts.map(v => `<span class="vuln-badge vuln-badge-${v.severity}">${v.count}</span>`).join(' ')
                        : '<span class="text-muted">None</span>'
                    }
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
                    Showing ${startItem}-${endItem} of ${this.total} scans
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
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Filter controls
        const applyFiltersBtn = document.getElementById('apply-filters-btn');
        const clearFiltersBtn = document.getElementById('clear-filters-btn');
        const repositoryInput = document.getElementById('filter-repository');
        const policyStatusSelect = document.getElementById('filter-policy-status');

        if (applyFiltersBtn) {
            applyFiltersBtn.addEventListener('click', async () => {
                const repository = repositoryInput.value.trim();
                const policyStatus = policyStatusSelect.value;

                this.setFilters({
                    repository: repository,
                    policy_passed: policyStatus === 'all' ? null : policyStatus === 'passed',
                });

                await this.loadAndRender();
            });
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', async () => {
                this.setFilters({
                    repository: '',
                    policy_passed: null,
                });

                await this.loadAndRender();
            });
        }

        // Allow Enter key to apply filters
        if (repositoryInput) {
            repositoryInput.addEventListener('keypress', (e) => {
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
                this.renderAndAttach();
            });
        });

        // Scan row click handlers
        document.querySelectorAll('.scan-row').forEach(row => {
            row.addEventListener('click', () => {
                const digest = row.dataset.digest;
                if (digest) {
                    // Don't encode here - the API client will encode it
                    window.router.navigate(`/scans/${digest}`);
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
                await this.loadAndRender();
            });
        }

        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', async () => {
                this.goToPage(this.currentPage - 1);
                await this.loadAndRender();
            });
        }

        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', async () => {
                this.goToPage(this.currentPage + 1);
                await this.loadAndRender();
            });
        }

        if (lastPageBtn) {
            lastPageBtn.addEventListener('click', async () => {
                const totalPages = Math.ceil(this.total / this.pageSize);
                this.goToPage(totalPages);
                await this.loadAndRender();
            });
        }

        // Rescan repository button
        const rescanBtn = document.getElementById('rescan-repository-btn');
        if (rescanBtn) {
            rescanBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                await this.handleRescanRepository();
            });
        }
    }

    /**
     * Handle repository rescan action
     */
    async handleRescanRepository() {
        const repository = this.filters.repository;
        
        if (!repository) {
            this.showNotification('No repository selected', 'error');
            return;
        }

        // Show confirmation dialog
        const confirmed = await Modal.confirm(
            'Rescan Repository',
            `Are you sure you want to trigger a rescan for all images in repository "${repository}"? This will queue scans for all images in this repository.`
        );

        if (!confirmed) {
            return;
        }

        try {
            // Disable button during operation
            const rescanBtn = document.getElementById('rescan-repository-btn');
            if (rescanBtn) {
                rescanBtn.disabled = true;
                rescanBtn.innerHTML = `
                    <span class="spinner-small"></span>
                    Triggering rescan...
                `;
            }

            // Trigger rescan via API
            const response = await this.apiClient.triggerScan({ repository });

            // Show success notification
            const message = response.message || `Repository rescan triggered successfully`;
            const taskInfo = response.task_id ? ` (Task ID: ${response.task_id})` : '';
            this.showNotification(message + taskInfo, 'success');

            // Reload scans after a short delay
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
            const rescanBtn = document.getElementById('rescan-repository-btn');
            if (rescanBtn) {
                rescanBtn.disabled = false;
                rescanBtn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                    </svg>
                    Rescan Repository: ${escapeHtml(repository)}
                `;
            }
        }
    }
}
