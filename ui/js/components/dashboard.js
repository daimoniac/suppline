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
        this.activeFilter = 'all'; // Filter state: 'all', 'expired', 'expiring', 'unused'
        this.data = {
            totalScans: 0,
            failedImages: 0,
            activeTolerations: 0,
            expiringTolerations: 0,
            expiringTolerationsDetails: [],
            expiredTolerationsDetails: [],
            unappliedTolerationsDetails: [],
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
                unappliedTolerations
            ] = await Promise.all([
                this.apiClient.getScans({ limit: 20 }),
                this.apiClient.getScans({ policy_passed: false }), 
                this.apiClient.getTolerations({}),
                this.apiClient.getUnappliedTolerations()
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

            // Process unapplied tolerations
            this.data.unappliedTolerationsDetails = Array.isArray(unappliedTolerations) ? unappliedTolerations : [];

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
                ${this.renderTolerationsRequiringAttention()}
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

                <div class="summary-card summary-card-secondary">
                    <div class="summary-card-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M9 11l3 3L22 4"></path>
                            <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"></path>
                        </svg>
                    </div>
                    <div class="summary-card-content">
                        <div class="summary-card-value">${this.data.unappliedTolerationsDetails.length.toLocaleString()}</div>
                        <div class="summary-card-label">Unapplied Tolerations</div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render tolerations requiring attention (expired, expiring, and unused)
     */
    renderTolerationsRequiringAttention() {
        const expiringCount = this.data.expiringTolerationsDetails.length;
        const expiredCount = this.data.expiredTolerationsDetails.length;
        const unusedCount = this.data.unappliedTolerationsDetails.length;
        const totalCount = expiringCount + expiredCount + unusedCount;

        if (totalCount === 0) {
            return '';
        }

        return `
            <div class="dashboard-section">
                <h2>Tolerations Requiring Attention</h2>
                <div class="tolerations-attention-summary">
                    ${expiredCount > 0 ? `<span class="attention-badge attention-badge-expired filter-badge" data-filter="expired">${expiredCount} Expired</span>` : ''}
                    ${expiringCount > 0 ? `<span class="attention-badge attention-badge-expiring filter-badge" data-filter="expiring">${expiringCount} Expiring Soon</span>` : ''}
                    ${unusedCount > 0 ? `<span class="attention-badge attention-badge-unused filter-badge" data-filter="unused">${unusedCount} Unused</span>` : ''}
                </div>
                <div class="tolerations-attention-list" id="tolerations-list">
                    ${this.renderFilteredTolerations()}
                </div>
            </div>
        `;
    }

    /**
     * Render filtered tolerations based on active filter
     */
    renderFilteredTolerations() {
        let items = [];

        if (this.activeFilter === 'all' || this.activeFilter === 'expired') {
            items = items.concat(this.renderExpiredTolerations());
        }
        if (this.activeFilter === 'all' || this.activeFilter === 'expiring') {
            items = items.concat(this.renderExpiringTolerations());
        }
        if (this.activeFilter === 'all' || this.activeFilter === 'unused') {
            items = items.concat(this.renderUnusedTolerations());
        }

        return items.join('');
    }

    /**
     * Render expired tolerations (shown first with alert styling)
     */
    renderExpiredTolerations() {
        if (this.data.expiredTolerationsDetails.length === 0) {
            return [];
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
                <div class="toleration-attention-item toleration-expired" data-cve="${escapeHtml(toleration.CVEID)}" data-type="expired">
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
        });
    }

    /**
     * Render expiring soon tolerations
     */
    renderExpiringTolerations() {
        if (this.data.expiringTolerationsDetails.length === 0) {
            return [];
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
                    <div class="toleration-attention-item toleration-expiring" data-cve="${escapeHtml(toleration.CVEID)}" data-type="expiring">
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
            });
    }

    /**
     * Render unused (unapplied) tolerations
     */
    renderUnusedTolerations() {
        if (this.data.unappliedTolerationsDetails.length === 0) {
            return [];
        }

        return this.data.unappliedTolerationsDetails.map(toleration => {
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

            const expiryDate = toleration.ExpiresAt ? new Date(toleration.ExpiresAt * 1000) : null;
            const expiryDateStr = expiryDate ? expiryDate.toLocaleDateString() : 'Never';

            return `
                <div class="toleration-attention-item toleration-unused" data-cve="${escapeHtml(toleration.CVEID)}" data-type="unused">
                    <div class="toleration-attention-header">
                        <span class="toleration-attention-cve">${escapeHtml(toleration.CVEID)}</span>
                        <span class="status-badge status-secondary">📋 UNUSED</span>
                    </div>
                    <div class="toleration-attention-repo">${repoDisplay}</div>
                    <div class="toleration-attention-statement">${escapeHtml(toleration.Statement || 'No statement provided')}</div>
                    <div class="toleration-attention-expiry">
                        Configured expiry: ${expiryDateStr}
                    </div>
                </div>
            `;
        });
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
            <tr class="scan-row" data-digest="${escapeHtml(scan.Digest)}" data-repository="${escapeHtml(scan.Repository || '')}">
                <td><span class="repository-link-cell" data-repository="${escapeHtml(scan.Repository || 'N/A')}">${escapeHtml(scan.Repository || 'N/A')}</span></td>
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
        // Add click handlers for filter badges
        document.querySelectorAll('.filter-badge').forEach(badge => {
            badge.addEventListener('click', (e) => {
                e.stopPropagation();
                const filter = badge.dataset.filter;
                
                // Toggle filter
                if (this.activeFilter === filter) {
                    this.activeFilter = 'all';
                } else {
                    this.activeFilter = filter;
                }
                
                // Update badge styling
                document.querySelectorAll('.filter-badge').forEach(b => {
                    b.classList.remove('filter-active');
                });
                if (this.activeFilter !== 'all') {
                    badge.classList.add('filter-active');
                }
                
                // Re-render filtered list
                const listContainer = document.getElementById('tolerations-list');
                if (listContainer) {
                    listContainer.innerHTML = this.renderFilteredTolerations();
                    // Re-attach click handlers for toleration items
                    this.attachTolerationItemHandlers();
                }
            });
        });

        // Add click handlers for scan rows
        document.querySelectorAll('.scan-row').forEach(row => {
            row.addEventListener('click', (e) => {
                // If clicking on the repository link cell, navigate to repository details instead
                if (e.target.classList.contains('repository-link-cell')) {
                    const repository = e.target.dataset.repository;
                    if (repository && repository !== 'N/A') {
                        window.router.navigate(`/repositories/${encodeURIComponent(repository)}`);
                    }
                } else {
                    // Otherwise navigate to tag details
                    const digest = row.dataset.digest;
                    if (digest) {
                        window.router.navigate(`/scans/${digest}`);
                    }
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
        this.attachTolerationItemHandlers();
        
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

    /**
     * Attach click handlers for toleration items (helper for re-use)
     */
    attachTolerationItemHandlers() {
        document.querySelectorAll('.toleration-attention-item').forEach(item => {
            item.addEventListener('click', () => {
                const cveId = item.dataset.cve;
                if (cveId) {
                    window.router.navigate(`/vulnerabilities?cve_id=${encodeURIComponent(cveId)}`);
                }
            });
        });
    }
}
