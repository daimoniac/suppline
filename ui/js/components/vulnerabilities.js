/**
 * Vulnerabilities Component
 * Search and analyze vulnerabilities across all scanned images.
 */

import { BaseComponent } from './base-component.js';
import { formatDate, formatRelativeTime } from '../utils/date.js';
import { truncateDigest } from '../utils/severity.js';

export class Vulnerabilities extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.vulnerabilities = [];
        this.groupedVulnerabilities = new Map();
        this.total = 0;
        this.currentPage = 1;
        this.pageSize = 100;
        this.filters = {
            cve_id: '',
            severity: '',
            package_name: '',
            repository: '',
        };
    }

    /**
     * Load vulnerabilities from API with current filters and pagination
     */
    async loadVulnerabilities() {
        try {
            const offset = (this.currentPage - 1) * this.pageSize;
            const apiFilters = {
                limit: this.pageSize,
                offset: offset,
            };

            if (this.filters.cve_id) {
                apiFilters.cve_id = this.filters.cve_id;
            }

            if (this.filters.severity) {
                apiFilters.severity = this.filters.severity;
            }

            if (this.filters.package_name) {
                apiFilters.package_name = this.filters.package_name;
            }

            if (this.filters.repository) {
                apiFilters.repository = this.filters.repository;
            }

            // API returns array directly
            const vulnerabilities = await this.apiClient.queryVulnerabilities(apiFilters);
            this.vulnerabilities = Array.isArray(vulnerabilities) ? vulnerabilities : [];
            this.total = this.vulnerabilities.length;

            // Group vulnerabilities by CVE ID
            this.groupVulnerabilities();

            return { vulnerabilities: this.vulnerabilities, total: this.total };
        } catch (error) {
            console.error('Failed to load vulnerabilities:', error);
            throw error;
        }
    }

    /**
     * Group vulnerabilities by CVE ID and count affected images
     */
    groupVulnerabilities() {
        this.groupedVulnerabilities.clear();

        this.vulnerabilities.forEach(vuln => {
            const cveId = vuln.CVEID || 'Unknown';
            
            if (!this.groupedVulnerabilities.has(cveId)) {
                this.groupedVulnerabilities.set(cveId, {
                    cveId: cveId,
                    severity: vuln.Severity,
                    description: vuln.Description || vuln.Title || 'No description available',
                    primaryURL: vuln.PrimaryURL,
                    affectedImages: [],
                });
            }

            const group = this.groupedVulnerabilities.get(cveId);
            
            // Add affected image info (avoid duplicates by digest)
            const existingImage = group.affectedImages.find(img => img.digest === vuln.Digest);
            if (!existingImage) {
                group.affectedImages.push({
                    digest: vuln.Digest,
                    repository: vuln.Repository,
                    tag: vuln.Tag,
                    packageName: vuln.PackageName,
                    installedVersion: vuln.InstalledVersion,
                    fixedVersion: vuln.FixedVersion,
                    scannedAt: vuln.ScannedAt,
                });
            }
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
     * Go to specific page
     */
    goToPage(page) {
        const totalPages = Math.ceil(this.total / this.pageSize);
        if (page >= 1 && page <= totalPages) {
            this.currentPage = page;
        }
    }

    /**
     * Render the complete vulnerabilities view
     */
    render() {
        return `
            <div class="vulnerabilities-list">
                <div class="vulnerabilities-header">
                    <h1>Vulnerability Search</h1>
                    <p class="vulnerabilities-subtitle">Search and analyze vulnerabilities across all scanned images</p>
                </div>

                ${this.renderSearchForm()}
                ${this.renderVulnerabilitiesResults()}
                ${this.renderPagination()}
            </div>
        `;
    }

    /**
     * Render search form with filters
     */
    renderSearchForm() {
        return `
            <div class="filters-container">
                <div class="filter-group">
                    <label for="filter-cve-id">CVE ID</label>
                    <input 
                        type="text" 
                        id="filter-cve-id" 
                        class="filter-input"
                        placeholder="e.g., CVE-2023-12345"
                        value="${this.escapeHtml(this.filters.cve_id)}"
                    />
                </div>

                <div class="filter-group">
                    <label for="filter-severity">Severity</label>
                    <select id="filter-severity" class="filter-select">
                        <option value="" ${this.filters.severity === '' ? 'selected' : ''}>All</option>
                        <option value="CRITICAL" ${this.filters.severity === 'CRITICAL' ? 'selected' : ''}>Critical</option>
                        <option value="HIGH" ${this.filters.severity === 'HIGH' ? 'selected' : ''}>High</option>
                        <option value="MEDIUM" ${this.filters.severity === 'MEDIUM' ? 'selected' : ''}>Medium</option>
                        <option value="LOW" ${this.filters.severity === 'LOW' ? 'selected' : ''}>Low</option>
                    </select>
                </div>

                <div class="filter-group">
                    <label for="filter-package-name">Package Name</label>
                    <input 
                        type="text" 
                        id="filter-package-name" 
                        class="filter-input"
                        placeholder="Filter by package name..."
                        value="${this.escapeHtml(this.filters.package_name)}"
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

                <div class="filter-actions">
                    <button id="search-vulnerabilities-btn" class="btn btn-primary">Search</button>
                    <button id="clear-filters-btn" class="btn btn-secondary">Clear</button>
                </div>
            </div>
        `;
    }

    /**
     * Render vulnerabilities results grouped by CVE ID
     */
    renderVulnerabilitiesResults() {
        if (this.groupedVulnerabilities.size === 0) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <circle cx="11" cy="11" r="8"></circle>
                        <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <h3>No vulnerabilities found</h3>
                    <p>Try adjusting your search filters or check back later</p>
                </div>
            `;
        }

        const groups = Array.from(this.groupedVulnerabilities.values());

        return `
            <div class="vulnerabilities-results">
                <div class="results-summary">
                    Found ${groups.length} unique CVE${groups.length !== 1 ? 's' : ''} 
                    affecting ${this.total} image${this.total !== 1 ? 's' : ''}
                </div>
                
                <div class="vulnerability-groups">
                    ${groups.map(group => this.renderVulnerabilityGroup(group)).join('')}
                </div>
            </div>
        `;
    }

    /**
     * Render individual vulnerability group
     */
    renderVulnerabilityGroup(group) {
        const severityClass = group.severity ? group.severity.toLowerCase() : 'unknown';
        const affectedCount = group.affectedImages.length;
        const groupId = `vuln-group-${this.escapeHtml(group.cveId).replace(/[^a-zA-Z0-9]/g, '-')}`;

        return `
            <div class="vulnerability-group card">
                <div class="vulnerability-group-header" data-group-id="${groupId}">
                    <div class="vulnerability-group-info">
                        <div class="vulnerability-group-title">
                            <span class="vuln-badge vuln-badge-${severityClass}">${this.escapeHtml(group.severity || 'UNKNOWN')}</span>
                            <h3 class="cve-id">${this.escapeHtml(group.cveId)}</h3>
                            <span class="affected-count">${affectedCount} affected image${affectedCount !== 1 ? 's' : ''}</span>
                        </div>
                        <p class="vulnerability-description">${this.escapeHtml(group.description)}</p>
                        ${group.primaryURL ? `
                            <a href="${this.escapeHtml(group.primaryURL)}" target="_blank" rel="noopener noreferrer" class="vulnerability-link">
                                View Details
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                    <polyline points="15 3 21 3 21 9"></polyline>
                                    <line x1="10" y1="14" x2="21" y2="3"></line>
                                </svg>
                            </a>
                        ` : ''}
                    </div>
                    <button class="expand-toggle" data-target="${groupId}" aria-expanded="false">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </button>
                </div>
                
                <div class="vulnerability-group-content collapsed" id="${groupId}">
                    ${this.renderAffectedImages(group.affectedImages)}
                </div>
            </div>
        `;
    }

    /**
     * Render affected images list
     */
    renderAffectedImages(images) {
        return `
            <div class="affected-images">
                <h4>Affected Images</h4>
                <div class="table-container">
                    <table class="affected-images-table">
                        <thead>
                            <tr>
                                <th>Repository</th>
                                <th>Tag</th>
                                <th>Digest</th>
                                <th>Package</th>
                                <th>Installed</th>
                                <th>Fixed In</th>
                                <th>Scanned</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${images.map(img => this.renderAffectedImageRow(img)).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    /**
     * Render individual affected image row
     */
    renderAffectedImageRow(image) {
        const truncatedDigest = truncateDigest(image.digest);
        const scanTime = formatRelativeTime(image.scannedAt);
        const fixedVersion = image.fixedVersion || 'N/A';

        return `
            <tr class="affected-image-row clickable" data-digest="${this.escapeHtml(image.digest)}">
                <td>${this.escapeHtml(image.repository || 'N/A')}</td>
                <td>${this.escapeHtml(image.tag || 'N/A')}</td>
                <td class="digest-cell" title="${this.escapeHtml(image.digest)}">${this.escapeHtml(truncatedDigest)}</td>
                <td>${this.escapeHtml(image.packageName || 'N/A')}</td>
                <td>${this.escapeHtml(image.installedVersion || 'N/A')}</td>
                <td>${this.escapeHtml(fixedVersion)}</td>
                <td title="${formatDate(image.scannedAt)}">${scanTime}</td>
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
                    Showing ${startItem}-${endItem} of ${this.total} vulnerabilities
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
        // Search form controls
        const searchBtn = document.getElementById('search-vulnerabilities-btn');
        const clearFiltersBtn = document.getElementById('clear-filters-btn');
        const cveIdInput = document.getElementById('filter-cve-id');
        const severitySelect = document.getElementById('filter-severity');
        const packageNameInput = document.getElementById('filter-package-name');
        const repositoryInput = document.getElementById('filter-repository');

        if (searchBtn) {
            searchBtn.addEventListener('click', async () => {
                const cveId = cveIdInput.value.trim();
                const severity = severitySelect.value;
                const packageName = packageNameInput.value.trim();
                const repository = repositoryInput.value.trim();

                this.setFilters({
                    cve_id: cveId,
                    severity: severity,
                    package_name: packageName,
                    repository: repository,
                });

                await this.loadAndRender();
            });
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', async () => {
                this.setFilters({
                    cve_id: '',
                    severity: '',
                    package_name: '',
                    repository: '',
                });

                await this.loadAndRender();
            });
        }

        // Allow Enter key to trigger search
        [cveIdInput, packageNameInput, repositoryInput].forEach(input => {
            if (input) {
                input.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        searchBtn.click();
                    }
                });
            }
        });

        // Expand/collapse toggle buttons
        document.querySelectorAll('.expand-toggle').forEach(button => {
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                const targetId = button.dataset.target;
                const content = document.getElementById(targetId);
                const isExpanded = button.getAttribute('aria-expanded') === 'true';

                if (content) {
                    if (isExpanded) {
                        content.classList.remove('expanded');
                        content.classList.add('collapsed');
                        button.setAttribute('aria-expanded', 'false');
                        button.classList.remove('expanded');
                    } else {
                        content.classList.remove('collapsed');
                        content.classList.add('expanded');
                        button.setAttribute('aria-expanded', 'true');
                        button.classList.add('expanded');
                    }
                }
            });
        });

        // Affected image row click handlers
        document.querySelectorAll('.affected-image-row').forEach(row => {
            row.addEventListener('click', () => {
                const digest = row.dataset.digest;
                if (digest) {
                    window.router.navigate(`/scans/${encodeURIComponent(digest)}`);
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
    }

    /**
     * Load data implementation for BaseComponent
     */
    async loadData() {
        await this.loadVulnerabilities();
    }
}
