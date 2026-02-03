/**
 * Dashboard Component
 * Displays overview of system security status including summary statistics,
 * vulnerability breakdown, and recent scan activity.
 */

import { BaseComponent } from './base-component.js';
import { escapeHtml } from '../utils/security.js';
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
            expiringTolerationsDetails: [],
            expiredTolerationsDetails: [],
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
                allTolerations
            ] = await Promise.all([
                this.apiClient.getScans({ limit: 20 }),
                this.apiClient.getScans({ policy_passed: false }), 
                this.apiClient.getTolerations({})
            ]);

            // Process recent scans (API returns array directly)
            this.data.recentScans = Array.isArray(recentScans) ? recentScans : [];

            // Process failed images
            const failedScansArray = Array.isArray(failedScans) ? failedScans : [];
            this.data.failedImages = failedScansArray.length;
            this.processFailedByRepository(failedScansArray);

            // Process tolerations - filter expired and expiring in the UI
            const tolerations = Array.isArray(allTolerations) ? allTolerations : [];
            this.data.activeTolerations = tolerations.length;
            
            // Filter tolerations by expiration status
            const now = Date.now();
            const sevenDaysFromNow = now + (7 * 24 * 60 * 60 * 1000);
            
            this.data.expiredTolerationsDetails = tolerations.filter(t => {
                return t.ExpiresAt && (t.ExpiresAt * 1000) <= now;
            });
            
            this.data.expiringTolerationsDetails = tolerations.filter(t => {
                if (!t.ExpiresAt) return false;
                const expiryMs = t.ExpiresAt * 1000;
                return expiryMs > now && expiryMs <= sevenDaysFromNow;
            });
            
            this.data.expiringTolerations = this.data.expiringTolerationsDetails.length;

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
                ${this.renderExpiringTolerationsCard()}
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
     * Render expiring and expired tolerations card
     */
    renderExpiringTolerationsCard() {
        const expiringCount = this.data.expiringTolerationsDetails.length;
        const expiredCount = this.data.expiredTolerationsDetails.length;
        const totalCount = expiringCount + expiredCount;

        if (totalCount === 0) {
            return '';
        }

        return `
            <div class="dashboard-section">
                <h2>Tolerations Requiring Attention</h2>
                <div class="tolerations-attention-summary">
                    ${expiredCount > 0 ? `<span class="attention-badge attention-badge-expired">${expiredCount} Expired</span>` : ''}
                    ${expiringCount > 0 ? `<span class="attention-badge attention-badge-expiring">${expiringCount} Expiring Soon</span>` : ''}
                </div>
                <div class="tolerations-attention-list">
                    ${this.renderExpiredTolerations()}
                    ${this.renderExpiringTolerations()}
                </div>
            </div>
        `;
    }

    /**
     * Render expired tolerations (shown first with alert styling)
     */
    renderExpiredTolerations() {
        if (this.data.expiredTolerationsDetails.length === 0) {
            return '';
        }

        return this.data.expiredTolerationsDetails.map(toleration => {
            const expiredDate = toleration.ExpiresAt ? new Date(toleration.ExpiresAt * 1000) : null;
            const expiredDateStr = expiredDate ? expiredDate.toLocaleDateString() : 'N/A';
            const daysExpired = expiredDate ? Math.floor((Date.now() - expiredDate.getTime()) / (1000 * 60 * 60 * 24)) : 0;
            
            // Handle repositories array - show up to 3, or "multiple repositories"
            const repositories = toleration.Repositories || [];
            let repoDisplay = '';
            if (repositories.length === 0) {
                repoDisplay = 'No repositories';
            } else if (repositories.length <= 3) {
                repoDisplay = repositories.map(r => escapeHtml(r.Repository)).join(', ');
            } else {
                repoDisplay = 'multiple repositories';
            }

            return `
                <div class="toleration-attention-item toleration-expired" data-cve="${escapeHtml(toleration.CVEID)}">
                    <div class="toleration-attention-header">
                        <span class="toleration-attention-cve">${escapeHtml(toleration.CVEID)}</span>
                        <span class="status-badge status-danger">⚠️ EXPIRED</span>
                    </div>
                    <div class="toleration-attention-repo">${repoDisplay}</div>
                    <div class="toleration-attention-statement">${escapeHtml(toleration.Statement || 'No statement provided')}</div>
                    <div class="toleration-attention-expiry toleration-attention-expiry-danger">
                        Expired ${daysExpired} day${daysExpired !== 1 ? 's' : ''} ago on ${expiredDateStr}
                    </div>
                </div>
            `;
        }).join('');
    }

    /**
     * Render expiring soon tolerations
     */
    renderExpiringTolerations() {
        if (this.data.expiringTolerationsDetails.length === 0) {
            return '';
        }

        // API already returns only non-expired items expiring within 7 days
        return this.data.expiringTolerationsDetails.map(toleration => {
                const expiryDate = toleration.ExpiresAt ? new Date(toleration.ExpiresAt * 1000) : null;
                const expiryDateStr = expiryDate ? expiryDate.toLocaleDateString() : 'Never';
                const daysUntilExpiry = expiryDate ? Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : null;
                
                // Handle repositories array - show up to 3, or "multiple repositories"
                const repositories = toleration.Repositories || [];
                let repoDisplay = '';
                if (repositories.length === 0) {
                    repoDisplay = 'No repositories';
                } else if (repositories.length <= 3) {
                    repoDisplay = repositories.map(r => escapeHtml(r.Repository)).join(', ');
                } else {
                    repoDisplay = 'multiple repositories';
                }

                return `
                    <div class="toleration-attention-item toleration-expiring" data-cve="${escapeHtml(toleration.CVEID)}">
                        <div class="toleration-attention-header">
                            <span class="toleration-attention-cve">${escapeHtml(toleration.CVEID)}</span>
                            <span class="status-badge status-warning">⏰ Expiring Soon</span>
                        </div>
                        <div class="toleration-attention-repo">${repoDisplay}</div>
                        <div class="toleration-attention-statement">${escapeHtml(toleration.Statement || 'No statement provided')}</div>
                        <div class="toleration-attention-expiry">
                            ${daysUntilExpiry !== null ? `Expires in ${daysUntilExpiry} day${daysUntilExpiry !== 1 ? 's' : ''} on ${expiryDateStr}` : 'No expiry date'}
                        </div>
                    </div>
                `;
            }).join('');
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
                <div class="repository-bar-label repository-link" data-repository="${escapeHtml(repo)}">${escapeHtml(repo)}</div>
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
            <tr class="scan-row" data-digest="${escapeHtml(scan.Digest)}">
                <td>${escapeHtml(scan.Repository || 'N/A')}</td>
                <td>${escapeHtml(scan.Tag || 'N/A')}</td>
                <td class="digest-cell" title="${escapeHtml(scan.Digest)}">${escapeHtml(truncatedDigest)}</td>
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

        // Add click handlers for toleration items
        document.querySelectorAll('.toleration-attention-item').forEach(item => {
            item.addEventListener('click', () => {
                const cveId = item.dataset.cve;
                if (cveId) {
                    window.router.navigate(`/vulnerabilities?cve_id=${encodeURIComponent(cveId)}`);
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
