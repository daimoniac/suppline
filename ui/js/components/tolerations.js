/**
 * Tolerations Component
 * Displays all CVE tolerations with filtering and expiration tracking.
 */

import { BaseComponent } from './base-component.js';
import { formatDate, formatRelativeTime, isPast, daysUntil, isWithinDays } from '../utils/date.js';
import { truncateText } from '../utils/helpers.js';

export class Tolerations extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.tolerations = [];
        this.total = 0;
        this.filters = {
            cve_id: '',
            repository: '',
            expiration_status: 'all', // all, active, expiring, expired
        };
        this.sortColumn = 'expires_at';
        this.sortDirection = 'asc';
    }

    /**
     * Load tolerations from API with current filters
     */
    async loadTolerations() {
        try {
            const apiFilters = {};

            if (this.filters.cve_id) {
                apiFilters.cve_id = this.filters.cve_id;
            }

            if (this.filters.repository) {
                apiFilters.repository = this.filters.repository;
            }

            // Map expiration status to API filters
            if (this.filters.expiration_status === 'expiring') {
                apiFilters.expiring_soon = true;
            } else if (this.filters.expiration_status === 'expired') {
                apiFilters.expired = true;
            }

            // API returns array directly (already deduplicated by backend)
            const tolerations = await this.apiClient.getTolerations(apiFilters);
            this.tolerations = Array.isArray(tolerations) ? tolerations : [];
            
            // Apply client-side filtering for 'active' status
            if (this.filters.expiration_status === 'active') {
                this.tolerations = this.tolerations.filter(t => !isPast(t.ExpiresAt) && !isWithinDays(t.ExpiresAt, 7));
            }

            this.total = this.tolerations.length;

            // Apply client-side sorting
            this.sortTolerations();

            return { tolerations: this.tolerations, total: this.total };
        } catch (error) {
            console.error('Failed to load tolerations:', error);
            throw error;
        }
    }



    /**
     * Get expiration status for a toleration
     */
    getExpirationStatus(toleration) {
        if (!toleration.ExpiresAt) return 'no-expiry';
        if (isPast(toleration.ExpiresAt)) return 'expired';
        if (isWithinDays(toleration.ExpiresAt, 7)) return 'expiring-soon';
        return 'active';
    }

    /**
     * Sort tolerations by current sort column and direction
     */
    sortTolerations() {
        const columnMap = {
            'cve_id': 'CVEID',
            'repository': 'Repository',
            'tag': 'Tag',
            'tolerated_at': 'ToleratedAt',
            'expires_at': 'ExpiresAt'
        };

        const apiColumn = columnMap[this.sortColumn] || this.sortColumn;

        this.tolerations.sort((a, b) => {
            let aVal = a[apiColumn];
            let bVal = b[apiColumn];

            // Handle null/undefined values (put them at the end)
            if (aVal === null || aVal === undefined) return 1;
            if (bVal === null || bVal === undefined) return -1;

            // Handle date sorting (Unix timestamps in seconds)
            if (this.sortColumn === 'tolerated_at' || this.sortColumn === 'expires_at') {
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
        this.sortTolerations();
    }

    /**
     * Render the complete tolerations view
     */
    render() {
        return `
            <div class="tolerations-list">
                <div class="tolerations-header">
                    <h1 class="page-title">CVE Tolerations</h1>
                    <p class="page-subtitle">View and manage approved CVE exceptions</p>
                </div>

                ${this.renderFilters()}
                ${this.renderTolerationsTable()}
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
                    <label for="filter-cve-id">CVE ID</label>
                    <input 
                        type="text" 
                        id="filter-cve-id" 
                        class="filter-input"
                        placeholder="Filter by CVE ID..."
                        value="${this.escapeHtml(this.filters.cve_id)}"
                    />
                </div>

                <div class="filter-group">
                    <label for="filter-repository">Repository</label>
                    <input 
                        type="text" 
                        id="filter-repository" 
                        class="filter-input"
                        placeholder="Filter by repository..."
                        value="${this.escapeHtml(this.filters.repository)}"
                    />
                </div>

                <div class="filter-group">
                    <label for="filter-expiration-status">Expiration Status</label>
                    <select id="filter-expiration-status" class="filter-select">
                        <option value="all" ${this.filters.expiration_status === 'all' ? 'selected' : ''}>All</option>
                        <option value="active" ${this.filters.expiration_status === 'active' ? 'selected' : ''}>Active</option>
                        <option value="expiring" ${this.filters.expiration_status === 'expiring' ? 'selected' : ''}>Expiring Soon</option>
                        <option value="expired" ${this.filters.expiration_status === 'expired' ? 'selected' : ''}>Expired</option>
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
     * Render tolerations table
     */
    renderTolerationsTable() {
        if (this.tolerations.length === 0) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                    </svg>
                    <h3>No tolerations found</h3>
                    <p>Try adjusting your filters or check back later</p>
                </div>
            `;
        }

        return `
            <div class="table-container">
                <table class="tolerations-table">
                    <thead>
                        <tr>
                            ${this.renderTableHeader('cve_id', 'CVE ID')}
                            ${this.renderTableHeader('repository', 'Repository')}
                            <th>Justification</th>
                            ${this.renderTableHeader('tolerated_at', 'Tolerated At')}
                            ${this.renderTableHeader('expires_at', 'Expires At')}
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.tolerations.map(toleration => this.renderTolerationRow(toleration)).join('')}
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
     * Render individual toleration row
     */
    renderTolerationRow(toleration) {
        const status = this.getExpirationStatus(toleration);
        const statusBadge = this.renderStatusBadge(status, toleration);
        const truncatedStatement = truncateText(toleration.Statement || 'N/A', 50);
        const toleratedTime = formatRelativeTime(toleration.ToleratedAt);
        const expiresDisplay = toleration.ExpiresAt 
            ? formatDate(toleration.ExpiresAt)
            : 'Never';

        return `
            <tr class="toleration-row clickable" data-repository="${this.escapeHtml(toleration.Repository)}" data-cve="${this.escapeHtml(toleration.CVEID)}">
                <td class="cve-cell">${this.escapeHtml(toleration.CVEID || 'N/A')}</td>
                <td>${this.escapeHtml(toleration.Repository || 'N/A')}</td>
                <td class="statement-cell" title="${this.escapeHtml(toleration.Statement || 'N/A')}">${this.escapeHtml(truncatedStatement)}</td>
                <td title="${formatDate(toleration.ToleratedAt)}">${toleratedTime}</td>
                <td>${expiresDisplay}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    }

    /**
     * Render status badge based on expiration status
     */
    renderStatusBadge(status, toleration) {
        switch (status) {
            case 'expired':
                return '<span class="status-badge status-danger">Expired</span>';
            case 'expiring-soon':
                const days = daysUntil(toleration.ExpiresAt);
                return `<span class="status-badge status-warning">Expires in ${days}d</span>`;
            case 'active':
                return '<span class="status-badge status-success">Active</span>';
            case 'no-expiry':
                return '<span class="status-badge status-info">No Expiry</span>';
            default:
                return '<span class="status-badge">Unknown</span>';
        }
    }

    /**
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Filter controls
        const applyFiltersBtn = document.getElementById('apply-filters-btn');
        const clearFiltersBtn = document.getElementById('clear-filters-btn');
        const cveIdInput = document.getElementById('filter-cve-id');
        const repositoryInput = document.getElementById('filter-repository');
        const expirationStatusSelect = document.getElementById('filter-expiration-status');

        if (applyFiltersBtn) {
            applyFiltersBtn.addEventListener('click', async () => {
                const cveId = cveIdInput.value.trim();
                const repository = repositoryInput.value.trim();
                const expirationStatus = expirationStatusSelect.value;

                this.setFilters({
                    cve_id: cveId,
                    repository: repository,
                    expiration_status: expirationStatus,
                });

                await this.loadAndRender();
            });
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', async () => {
                this.setFilters({
                    cve_id: '',
                    repository: '',
                    expiration_status: 'all',
                });

                await this.loadAndRender();
            });
        }

        // Allow Enter key to apply filters
        [cveIdInput, repositoryInput].forEach(input => {
            if (input) {
                input.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        applyFiltersBtn.click();
                    }
                });
            }
        });

        // Sortable column headers
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', async () => {
                const column = header.dataset.column;
                this.setSort(column);
                this.renderAndAttach();
            });
        });

        // Toleration row click handlers - navigate to scans filtered by repository
        document.querySelectorAll('.toleration-row').forEach(row => {
            row.addEventListener('click', () => {
                const repository = row.dataset.repository;
                if (repository) {
                    window.router.navigate(`/scans?repository=${encodeURIComponent(repository)}`);
                }
            });
        });
    }

    /**
     * Load data - implements BaseComponent interface
     */
    async loadData() {
        await this.loadTolerations();
    }
}


/**
 * Expiring Tolerations Component
 * Displays tolerations expiring within 7 days with urgency highlighting.
 */
export class ExpiringTolerations extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.tolerations = [];
        this.total = 0;
        this.sortColumn = 'expires_at';
        this.sortDirection = 'asc';
    }

    /**
     * Load expiring tolerations from API
     */
    async loadExpiringTolerations() {
        try {
            // API returns array directly
            const tolerations = await this.apiClient.getTolerations({ expiring_soon: true });
            this.tolerations = Array.isArray(tolerations) ? tolerations : [];
            this.total = this.tolerations.length;

            // Sort by expiration date ascending (most urgent first)
            this.sortTolerations();

            return { tolerations: this.tolerations, total: this.total };
        } catch (error) {
            console.error('Failed to load expiring tolerations:', error);
            throw error;
        }
    }

    /**
     * Get urgency level based on days until expiration
     */
    getUrgencyLevel(toleration) {
        const days = daysUntil(toleration.ExpiresAt);
        if (days === null) return 'none';
        if (days < 0) return 'expired';
        if (days <= 1) return 'critical';
        if (days <= 3) return 'high';
        return 'medium';
    }

    /**
     * Sort tolerations by expiration date
     */
    sortTolerations() {
        const columnMap = {
            'cve_id': 'CVEID',
            'repository': 'Repository',
            'tolerated_at': 'ToleratedAt',
            'expires_at': 'ExpiresAt'
        };

        const apiColumn = columnMap[this.sortColumn] || this.sortColumn;

        this.tolerations.sort((a, b) => {
            let aVal = a[apiColumn];
            let bVal = b[apiColumn];

            // Handle null/undefined values
            if (aVal === null || aVal === undefined) return 1;
            if (bVal === null || bVal === undefined) return -1;

            // Handle date sorting (Unix timestamps in seconds)
            if (this.sortColumn === 'tolerated_at' || this.sortColumn === 'expires_at') {
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
        this.sortTolerations();
    }

    /**
     * Render the complete expiring tolerations view
     */
    render() {
        return `
            <div class="expiring-tolerations-list">
                <div class="expiring-tolerations-header">
                    <h1 class="page-title">Expiring Tolerations</h1>
                    <p class="page-subtitle">CVE tolerations expiring within 7 days</p>
                </div>

                ${this.renderAlert()}
                ${this.renderExpiringTolerationsTable()}
            </div>
        `;
    }

    /**
     * Render alert banner
     */
    renderAlert() {
        if (this.tolerations.length === 0) {
            return '';
        }

        const criticalCount = this.tolerations.filter(t => this.getUrgencyLevel(t) === 'critical').length;
        const highCount = this.tolerations.filter(t => this.getUrgencyLevel(t) === 'high').length;

        return `
            <div class="expiring-alert">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                <div class="expiring-alert-content">
                    <div class="expiring-alert-title">Action Required</div>
                    <div class="expiring-alert-message">
                        ${this.total} toleration${this.total !== 1 ? 's' : ''} expiring soon
                        ${criticalCount > 0 ? ` (${criticalCount} within 24 hours)` : ''}
                        ${highCount > 0 ? ` (${highCount} within 3 days)` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render expiring tolerations table
     */
    renderExpiringTolerationsTable() {
        if (this.tolerations.length === 0) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M12 6v6l4 2"></path>
                    </svg>
                    <h3>No expiring tolerations</h3>
                    <p>All tolerations are valid for more than 7 days</p>
                </div>
            `;
        }

        return `
            <div class="table-container">
                <table class="expiring-tolerations-table">
                    <thead>
                        <tr>
                            <th>Urgency</th>
                            ${this.renderTableHeader('cve_id', 'CVE ID')}
                            ${this.renderTableHeader('repository', 'Repository')}
                            <th>Justification</th>
                            ${this.renderTableHeader('expires_at', 'Expires At')}
                            <th>Days Left</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.tolerations.map(toleration => this.renderTolerationRow(toleration)).join('')}
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
     * Render individual toleration row with urgency highlighting
     */
    renderTolerationRow(toleration) {
        const urgency = this.getUrgencyLevel(toleration);
        const urgencyBadge = this.renderUrgencyBadge(urgency);
        const daysLeft = daysUntil(toleration.ExpiresAt);
        const daysLeftDisplay = daysLeft !== null 
            ? (daysLeft < 0 ? 'Expired' : `${daysLeft} day${daysLeft !== 1 ? 's' : ''}`)
            : 'N/A';
        const truncatedStatement = truncateText(toleration.Statement || 'N/A', 50);
        const expiresDisplay = toleration.ExpiresAt 
            ? formatDate(toleration.ExpiresAt)
            : 'Never';

        // Add row class based on urgency
        const rowClass = urgency === 'critical' ? 'urgency-critical' : 
                        urgency === 'high' ? 'urgency-high' : 
                        urgency === 'expired' ? 'urgency-expired' : '';

        return `
            <tr class="toleration-row clickable ${rowClass}" data-repository="${this.escapeHtml(toleration.Repository)}" data-cve="${this.escapeHtml(toleration.CVEID)}">
                <td>${urgencyBadge}</td>
                <td class="cve-cell">${this.escapeHtml(toleration.CVEID || 'N/A')}</td>
                <td>${this.escapeHtml(toleration.Repository || 'N/A')}</td>
                <td class="statement-cell" title="${this.escapeHtml(toleration.Statement || 'N/A')}">${this.escapeHtml(truncatedStatement)}</td>
                <td>${expiresDisplay}</td>
                <td><strong>${daysLeftDisplay}</strong></td>
            </tr>
        `;
    }

    /**
     * Render urgency badge
     */
    renderUrgencyBadge(urgency) {
        switch (urgency) {
            case 'expired':
                return '<span class="status-badge status-danger">Expired</span>';
            case 'critical':
                return '<span class="status-badge status-danger">Critical</span>';
            case 'high':
                return '<span class="status-badge status-warning">High</span>';
            case 'medium':
                return '<span class="status-badge status-warning">Medium</span>';
            default:
                return '<span class="status-badge">Unknown</span>';
        }
    }

    /**
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Sortable column headers
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', async () => {
                const column = header.dataset.column;
                this.setSort(column);
                this.renderAndAttach();
            });
        });

        // Toleration row click handlers - navigate to scans filtered by repository
        document.querySelectorAll('.toleration-row').forEach(row => {
            row.addEventListener('click', () => {
                const repository = row.dataset.repository;
                if (repository) {
                    window.router.navigate(`/scans?repository=${encodeURIComponent(repository)}`);
                }
            });
        });
    }

    /**
     * Load data - implements BaseComponent interface
     */
    async loadData() {
        await this.loadExpiringTolerations();
    }
}
