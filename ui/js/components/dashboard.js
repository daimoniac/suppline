/**
 * Dashboard Component
 * Displays overview of system security status including summary statistics,
 * vulnerability breakdown, and recent scan activity.
 */

import { BaseComponent } from './base-component.js';
import { formatRelativeTime } from '../utils/date.js';
import { getSeverityBadge } from '../utils/severity.js';

export class Dashboard extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.data = {
            totalScans: 0,
            failedImages: 0,
            activeTolerations: 0,
            expiringTolerations: 0,
            recentScans: [],
            vulnerabilityBreakdown: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            },
            failedByRepository: {}
        };
    }

    /**
     * Load all dashboard data from API
     */
    async loadData() {
        try {
            // Fetch data in parallel for better performance
            // API returns arrays directly, not wrapped objects
            const [
                recentScans,
                failedScans,
                allTolerations,
                expiringTolerations
            ] = await Promise.all([
                this.apiClient.getScans({ limit: 20 }),
                this.apiClient.getScans({ policy_passed: false }), 
                this.apiClient.getTolerations({}),
                this.apiClient.getTolerations({ expiring_soon: true })
            ]);

            // Process recent scans (API returns array directly)
            this.data.recentScans = Array.isArray(recentScans) ? recentScans : [];

            // Process failed images
            const failedScansArray = Array.isArray(failedScans) ? failedScans : [];
            this.data.failedImages = failedScansArray.length;
            this.processFailedByRepository(failedScansArray);

            // Process tolerations (API returns array directly)
            this.data.activeTolerations = Array.isArray(allTolerations) ? allTolerations.length : 0;
            this.data.expiringTolerations = Array.isArray(expiringTolerations) ? expiringTolerations.length : 0;

            // Calculate vulnerability breakdown from recent scans
            this.calculateVulnerabilityBreakdown(this.data.recentScans);

            return this.data;
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            throw error;
        }
    }

    /**
     * Process failed scans to group by repository
     */
    processFailedByRepository(failedScans) {
        this.data.failedByRepository = {};
        failedScans.forEach(scan => {
            const repo = scan.Repository || 'unknown';
            if (!this.data.failedByRepository[repo]) {
                this.data.failedByRepository[repo] = 0;
            }
            this.data.failedByRepository[repo]++;
        });
    }

    /**
     * Calculate vulnerability breakdown across all scans
     */
    calculateVulnerabilityBreakdown(scans) {
        this.data.vulnerabilityBreakdown = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        scans.forEach(scan => {
            this.data.vulnerabilityBreakdown.critical += scan.CriticalVulnCount || 0;
            this.data.vulnerabilityBreakdown.high += scan.HighVulnCount || 0;
            this.data.vulnerabilityBreakdown.medium += scan.MediumVulnCount || 0;
            this.data.vulnerabilityBreakdown.low += scan.LowVulnCount || 0;
        });
    }

    /**
     * Render the complete dashboard
     */
    render() {
        return `
            <div class="dashboard">
                <div class="dashboard-header">
                    <h1 class="page-title">Security Dashboard</h1>
                    <p class="page-subtitle">Container Image Security Overview</p>
                </div>

                ${this.renderSummaryCards()}
                ${this.renderVulnerabilityBreakdown()}
                ${this.renderFailedByRepository()}
                ${this.renderRecentScans()}
            </div>
        `;
    }

    /**
     * Render summary statistics cards
     */
    renderSummaryCards() {
        return `
            <div class="summary-cards">
                <div class="summary-card summary-card-danger">
                    <div class="summary-card-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                    </div>
                    <div class="summary-card-content">
                        <div class="summary-card-value">${this.data.failedImages.toLocaleString()}</div>
                        <div class="summary-card-label">Failed Scans (24h)</div>
                    </div>
                </div>

                <div class="summary-card summary-card-info">
                    <div class="summary-card-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                            <line x1="16" y1="13" x2="8" y2="13"></line>
                            <line x1="16" y1="17" x2="8" y2="17"></line>
                            <polyline points="10 9 9 9 8 9"></polyline>
                        </svg>
                    </div>
                    <div class="summary-card-content">
                        <div class="summary-card-value">${this.data.activeTolerations.toLocaleString()}</div>
                        <div class="summary-card-label">Active Tolerations</div>
                    </div>
                </div>

                <div class="summary-card summary-card-warning">
                    <div class="summary-card-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <polyline points="12 6 12 12 16 14"></polyline>
                        </svg>
                    </div>
                    <div class="summary-card-content">
                        <div class="summary-card-value">${this.data.expiringTolerations.toLocaleString()}</div>
                        <div class="summary-card-label">Expiring Soon</div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render vulnerability severity breakdown
     */
    renderVulnerabilityBreakdown() {
        const breakdown = this.data.vulnerabilityBreakdown;
        const total = breakdown.critical + breakdown.high + breakdown.medium + breakdown.low;

        if (total === 0) {
            return `
                <div class="dashboard-section">
                    <h2>Vulnerability Breakdown</h2>
                    <div class="empty-state">
                        <p>No vulnerabilities found in recent scans</p>
                    </div>
                </div>
            `;
        }

        return `
            <div class="dashboard-section">
                <h2>Vulnerability Breakdown</h2>
                <div class="vulnerability-breakdown">
                    <div class="vulnerability-bar">
                        ${this.renderVulnerabilityBar(breakdown, total)}
                    </div>
                    <div class="vulnerability-stats">
                        ${this.renderVulnerabilityStat('critical', breakdown.critical, total)}
                        ${this.renderVulnerabilityStat('high', breakdown.high, total)}
                        ${this.renderVulnerabilityStat('medium', breakdown.medium, total)}
                        ${this.renderVulnerabilityStat('low', breakdown.low, total)}
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render vulnerability bar chart
     */
    renderVulnerabilityBar(breakdown, total) {
        const criticalPct = (breakdown.critical / total * 100).toFixed(1);
        const highPct = (breakdown.high / total * 100).toFixed(1);
        const mediumPct = (breakdown.medium / total * 100).toFixed(1);
        const lowPct = (breakdown.low / total * 100).toFixed(1);

        let html = '';
        if (breakdown.critical > 0) {
            html += `<div class="vulnerability-bar-segment vulnerability-bar-critical" data-width="${criticalPct}" title="Critical: ${breakdown.critical}"></div>`;
        }
        if (breakdown.high > 0) {
            html += `<div class="vulnerability-bar-segment vulnerability-bar-high" data-width="${highPct}" title="High: ${breakdown.high}"></div>`;
        }
        if (breakdown.medium > 0) {
            html += `<div class="vulnerability-bar-segment vulnerability-bar-medium" data-width="${mediumPct}" title="Medium: ${breakdown.medium}"></div>`;
        }
        if (breakdown.low > 0) {
            html += `<div class="vulnerability-bar-segment vulnerability-bar-low" data-width="${lowPct}" title="Low: ${breakdown.low}"></div>`;
        }

        return html;
    }

    /**
     * Render individual vulnerability stat
     */
    renderVulnerabilityStat(severity, count, total) {
        const percentage = total > 0 ? (count / total * 100).toFixed(1) : 0;
        const badge = getSeverityBadge(severity);

        return `
            <div class="vulnerability-stat">
                ${badge}
                <div class="vulnerability-stat-count">${count.toLocaleString()}</div>
                <div class="vulnerability-stat-percentage">${percentage}%</div>
            </div>
        `;
    }

    /**
     * Render failed images by repository
     */
    renderFailedByRepository() {
        const repos = Object.entries(this.data.failedByRepository)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);

        if (repos.length === 0) {
            return `
                <div class="dashboard-section">
                    <h2>Policy Compliance Status</h2>
                    <div class="success-state">
                        <div class="success-icon">🎆</div>
                        <h3>Great Success!</h3>
                        <p>All images are compliant to policy.</p>
                    </div>
                </div>
            `;
        }

        return `
            <div class="dashboard-section">
                <h2>Policy Compliance Status</h2>
                <div class="repository-chart">
                    ${repos.map(([repo, count]) => this.renderRepositoryBar(repo, count)).join('')}
                </div>
            </div>
        `;
    }

    /**
     * Render repository bar
     */
    renderRepositoryBar(repo, count) {
        const maxCount = Math.max(...Object.values(this.data.failedByRepository));
        const percentage = (count / maxCount * 100).toFixed(1);

        return `
            <div class="repository-bar-item">
                <div class="repository-bar-label repository-link" data-repository="${this.escapeHtml(repo)}">${this.escapeHtml(repo)}</div>
                <div class="repository-bar-container">
                    <div class="repository-bar-fill" data-width="${percentage}"></div>
                    <div class="repository-bar-count">${count}</div>
                </div>
            </div>
        `;
    }

    /**
     * Render recent scans table
     */
    renderRecentScans() {
        if (this.data.recentScans.length === 0) {
            return `
                <div class="dashboard-section">
                    <h2>Recent Scans</h2>
                    <div class="empty-state">
                        <p>No scans found</p>
                    </div>
                </div>
            `;
        }

        return `
            <div class="dashboard-section">
                <h2>Recent Scans</h2>
                <div class="table-container">
                    <table class="scans-table">
                        <thead>
                            <tr>
                                <th>Repository</th>
                                <th>Tag</th>
                                <th>Digest</th>
                                <th>Scanned</th>
                                <th>Status</th>
                                <th>Vulnerabilities</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${this.data.recentScans.map(scan => this.renderScanRow(scan)).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    /**
     * Render individual scan row
     */
    renderScanRow(scan) {
        const statusClass = scan.PolicyPassed ? 'status-success' : 'status-danger';
        const statusText = scan.PolicyPassed ? 'Passed' : 'Failed';
        const truncatedDigest = scan.Digest ? scan.Digest.substring(0, 19) + '...' : 'N/A';
        const scanTime = formatRelativeTime(scan.CreatedAt);

        const vulnCounts = [
            { severity: 'critical', count: scan.CriticalVulnCount || 0 },
            { severity: 'high', count: scan.HighVulnCount || 0 },
            { severity: 'medium', count: scan.MediumVulnCount || 0 },
            { severity: 'low', count: scan.LowVulnCount || 0 }
        ].filter(v => v.count > 0);

        return `
            <tr class="scan-row" data-digest="${this.escapeHtml(scan.Digest)}">
                <td>${this.escapeHtml(scan.Repository || 'N/A')}</td>
                <td>${this.escapeHtml(scan.Tag || 'N/A')}</td>
                <td class="digest-cell" title="${this.escapeHtml(scan.Digest)}">${this.escapeHtml(truncatedDigest)}</td>
                <td>${scanTime}</td>
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
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Add click handlers for scan rows
        document.querySelectorAll('.scan-row').forEach(row => {
            row.addEventListener('click', () => {
                const digest = row.dataset.digest;
                if (digest) {
                    window.router.navigate(`/scans/${digest}`);
                }
            });
        });

        // Add click handlers for repository names in failed scans chart
        document.querySelectorAll('.repository-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.stopPropagation();
                const repository = link.dataset.repository;
                if (repository) {
                    window.router.navigate(`/repositories/${encodeURIComponent(repository)}`);
                }
            });
        });
        
        // Apply widths to vulnerability bar segments
        document.querySelectorAll('.vulnerability-bar-segment[data-width]').forEach(segment => {
            const width = segment.dataset.width;
            if (width) {
                segment.style.setProperty('--bar-width', `${width}%`);
            }
        });
        
        // Apply widths to repository bar fills
        document.querySelectorAll('.repository-bar-fill[data-width]').forEach(fill => {
            const width = fill.dataset.width;
            if (width) {
                fill.style.setProperty('--bar-width', `${width}%`);
            }
        });
    }
}
