/**
 * Failed Images Component
 * Displays policy-failed images with vulnerability breakdown and failure reasons.
 * Reuses the ScansList component with policy_passed=false filter.
 */

import { ScansList } from './scans.js';
import { formatDate, formatRelativeTime } from '../utils/date.js';
import { truncateDigest } from '../utils/severity.js';

export class FailedImages extends ScansList {
    constructor(apiClient) {
        super(apiClient);
        // Pre-configure filters for failed images only
        this.filters.policy_passed = false;
        this.pageTitle = 'Failed Images';
        this.pageSubtitle = 'Images that failed security policy evaluation';
    }

    /**
     * Render the complete failed images view
     */
    render() {
        return `
            <div class="failed-images-list">
                <div class="failed-images-header">
                    <h1 class="page-title">${this.pageTitle}</h1>
                    <p class="page-subtitle">${this.pageSubtitle}</p>
                </div>

                ${this.renderFailureAlert()}
                ${this.renderFilters()}
                ${this.renderRescanButton()}
                ${this.renderFailedImagesTable()}
                ${this.renderPagination()}
            </div>
        `;
    }

    /**
     * Render alert banner for failed images
     */
    renderFailureAlert() {
        if (this.scans.length === 0) {
            return '';
        }

        const totalCritical = this.scans.reduce((sum, scan) => sum + (scan.CriticalVulnCount || 0), 0);
        const totalHigh = this.scans.reduce((sum, scan) => sum + (scan.HighVulnCount || 0), 0);

        return `
            <div class="failure-alert">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                <div class="failure-alert-content">
                    <div class="failure-alert-title">Policy Failures Detected</div>
                    <div class="failure-alert-message">
                        ${this.scans.length} image${this.scans.length !== 1 ? 's' : ''} failed security policy evaluation.
                        ${totalCritical > 0 ? `${totalCritical} critical` : ''}${totalCritical > 0 && totalHigh > 0 ? ' and ' : ''}${totalHigh > 0 ? `${totalHigh} high` : ''} vulnerabilities detected.
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render filter controls (simplified for failed images)
     */
    renderFilters() {
        return `
            <div class="filters-container">
                <div class="filter-group">
                    <label for="filter-repository">Repository</label>
                    <input 
                        type="text" 
                        id="filter-repository" 
                        class="filter-input"
                        placeholder="Filter by repository name..."
                        value="${this.escapeHtml(this.filters.repository)}"
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
     * Render failed images table with enhanced vulnerability breakdown
     */
    renderFailedImagesTable() {
        if (this.scans.length === 0) {
            return `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                        <polyline points="22 4 12 14.01 9 11.01"></polyline>
                    </svg>
                    <h3>No Failed Images</h3>
                    <p>All scanned images are passing security policy evaluation</p>
                </div>
            `;
        }

        return `
            <div class="table-container">
                <table class="failed-images-table">
                    <thead>
                        <tr>
                            ${this.renderTableHeader('repository', 'Repository')}
                            ${this.renderTableHeader('tag', 'Tag')}
                            ${this.renderTableHeader('digest', 'Digest')}
                            ${this.renderTableHeader('scanned_at', 'Scanned')}
                            <th>Vulnerability Breakdown</th>
                            <th>Failure Reasons</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.scans.map(scan => this.renderFailedImageRow(scan)).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    /**
     * Render individual failed image row with enhanced details
     */
    renderFailedImageRow(scan) {
        const truncatedDigest = truncateDigest(scan.Digest);
        const scanTime = formatRelativeTime(scan.CreatedAt);

        // Build vulnerability breakdown
        const vulnBreakdown = this.renderVulnerabilityBreakdown(scan);

        // Build failure reasons
        const failureReasons = this.renderFailureReasons(scan);

        return `
            <tr class="failed-image-row clickable" data-digest="${this.escapeHtml(scan.Digest)}">
                <td>${this.escapeHtml(scan.Repository || 'N/A')}</td>
                <td>${this.escapeHtml(scan.Tag || 'N/A')}</td>
                <td class="digest-cell" title="${this.escapeHtml(scan.Digest)}">${this.escapeHtml(truncatedDigest)}</td>
                <td title="${formatDate(scan.CreatedAt)}">${scanTime}</td>
                <td class="vulnerability-breakdown-cell">
                    ${vulnBreakdown}
                </td>
                <td class="failure-reasons-cell">
                    ${failureReasons}
                </td>
            </tr>
        `;
    }

    /**
     * Render vulnerability breakdown with detailed counts
     */
    renderVulnerabilityBreakdown(scan) {
        const vulnCounts = [
            { severity: 'critical', count: scan.CriticalVulnCount || 0, label: 'Critical' },
            { severity: 'high', count: scan.HighVulnCount || 0, label: 'High' },
            { severity: 'medium', count: scan.MediumVulnCount || 0, label: 'Medium' },
            { severity: 'low', count: scan.LowVulnCount || 0, label: 'Low' }
        ];

        const hasVulnerabilities = vulnCounts.some(v => v.count > 0);

        if (!hasVulnerabilities) {
            return '<span class="text-muted">None</span>';
        }

        return `
            <div class="vulnerability-breakdown-inline">
                ${vulnCounts
                    .filter(v => v.count > 0)
                    .map(v => `
                        <div class="vuln-count-item">
                            <span class="vuln-badge vuln-badge-${v.severity}">${v.count}</span>
                            <span class="vuln-label">${v.label}</span>
                        </div>
                    `).join('')}
            </div>
        `;
    }

    /**
     * Render failure reasons highlighting why the image failed
     */
    renderFailureReasons(scan) {
        const reasons = [];

        // Check for critical/high vulnerabilities (primary failure reason)
        const criticalCount = scan.CriticalVulnCount || 0;
        const highCount = scan.HighVulnCount || 0;

        if (criticalCount > 0) {
            reasons.push(`<span class="failure-reason failure-reason-critical">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                ${criticalCount} Critical CVE${criticalCount !== 1 ? 's' : ''}
            </span>`);
        }

        if (highCount > 0) {
            reasons.push(`<span class="failure-reason failure-reason-high">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                ${highCount} High CVE${highCount !== 1 ? 's' : ''}
            </span>`);
        }

        // Check attestation status (signing removed)

        if (!scan.VulnAttested) {
            reasons.push(`<span class="failure-reason failure-reason-warning">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                </svg>
                No Vuln Attestation
            </span>`);
        }

        if (reasons.length === 0) {
            return '<span class="text-muted">Unknown</span>';
        }

        return `<div class="failure-reasons-list">${reasons.join('')}</div>`;
    }

    /**
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Filter controls
        const applyFiltersBtn = document.getElementById('apply-filters-btn');
        const clearFiltersBtn = document.getElementById('clear-filters-btn');
        const repositoryInput = document.getElementById('filter-repository');

        if (applyFiltersBtn) {
            applyFiltersBtn.addEventListener('click', async () => {
                const repository = repositoryInput.value.trim();

                this.setFilters({
                    repository: repository,
                    policy_passed: false, // Always filter for failed images
                });

                await this.loadAndRender();
            });
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', async () => {
                this.setFilters({
                    repository: '',
                    policy_passed: false, // Always filter for failed images
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

        // Failed image row click handlers
        document.querySelectorAll('.failed-image-row').forEach(row => {
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

        // Rescan repository button
        const rescanBtn = document.getElementById('rescan-repository-btn');
        if (rescanBtn) {
            rescanBtn.addEventListener('click', () => {
                this.handleRescanRepository();
            });
        }
    }
}
