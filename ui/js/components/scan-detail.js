/**
 * Scan Detail Component
 * Displays detailed information about a specific image scan including
 * vulnerabilities, tolerations, attestation status, and rescan actions.
 */

import { BaseComponent } from './base-component.js';
import { formatDate, formatRelativeTime, formatExpirationStatus, getExpirationStatusClass } from '../utils/date.js';
import { 
    getSeverityBadge, 
    truncateDigest,
    formatVersions,
    groupBySeverity
} from '../utils/severity.js';

export class ScanDetail extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.scan = null;
        this.digest = null;
        this.expandedSeverities = new Set(); // Track which severity groups are expanded
        this.expandedTolerations = new Set(); // Track which tolerations are expanded
    }

    /**
     * Load scan details from API
     * @param {string} digest - Image digest
     */
    async loadScan(digest) {
        try {
            this.digest = digest;
            // API returns single ScanRecord object with PascalCase fields
            this.scan = await this.apiClient.getScanByDigest(digest);
            return this.scan;
        } catch (error) {
            console.error('Failed to load scan details:', error);
            throw error;
        }
    }

    /**
     * Render the complete scan detail view
     */
    render() {
        if (!this.scan) {
            return this.renderError('Scan data not available');
        }

        return `
            <div class="scan-detail">
                <div class="scan-detail-header">
                    <button class="btn btn-secondary btn-sm back-button" id="back-to-scans">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="19" y1="12" x2="5" y2="12"></line>
                            <polyline points="12 19 5 12 12 5"></polyline>
                        </svg>
                        Back to Scans
                    </button>
                    <h1 class="scan-detail-title">Scan Details</h1>
                    <p class="scan-detail-subtitle">Detailed information about this image scan</p>
                </div>

                ${this.renderImageInformation()}
                ${this.renderVulnerabilitySummary()}
                ${this.renderVulnerabilityList()}
                ${this.renderTolerations()}
            </div>
        `;
    }

    /**
     * Render image information section
     */
    renderImageInformation() {
        const statusClass = this.scan.PolicyPassed ? 'status-success' : 'status-danger';
        const statusText = this.scan.PolicyPassed ? 'Passed' : 'Failed';
        const scanTime = formatDate(this.scan.ScannedAt);
        const relativeTime = formatRelativeTime(this.scan.ScannedAt);

        return `
            <div class="dashboard-section scan-section">
                <h2>Image Information</h2>
                <div class="info-grid">
                    <div>
                        <div class="info-label">Repository</div>
                        <div class="info-value">${this.escapeHtml(this.scan.Repository || 'N/A')}</div>
                    </div>
                    <div>
                        <div class="info-label">Tag</div>
                        <div class="info-value">${this.escapeHtml(this.scan.Tag || 'N/A')}</div>
                    </div>
                    <div>
                        <div class="info-label">Digest</div>
                        <div class="digest-cell" title="${this.escapeHtml(this.scan.Digest)}">${this.escapeHtml(truncateDigest(this.scan.Digest))}</div>
                    </div>
                    <div>
                        <div class="info-label">Scanned</div>
                        <div title="${scanTime}">${relativeTime}</div>
                    </div>
                    <div>
                        <div class="info-label">Policy Status</div>
                        <div><span class="status-badge ${statusClass}">${statusText}</span></div>
                    </div>
                    <div>
                        <div class="info-label">Attestation Status</div>
                        <div class="attestation-badges">
                            ${this.renderAttestationIndicator('SBOM', this.scan.SBOMAttested)}
                            ${this.renderAttestationIndicator('Vuln', this.scan.VulnAttested)}
                            ${this.renderAttestationIndicator('Signed', this.scan.Signed)}
                        </div>
                    </div>
                </div>
                ${this.renderRescanButton()}
            </div>
        `;
    }

    /**
     * Render attestation status indicator
     */
    renderAttestationIndicator(label, attested) {
        const badgeClass = attested ? 'badge-success' : 'badge-danger';
        const icon = attested 
            ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>'
            : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
        
        return `
            <span class="badge attestation-badge ${badgeClass}" title="${label}: ${attested ? 'Yes' : 'No'}">
                ${icon}
                <span class="attestation-label">${label}</span>
            </span>
        `;
    }

    /**
     * Render rescan action button
     */
    renderRescanButton() {
        return `
            <div class="rescan-button-container">
                <button id="trigger-rescan-btn" class="btn btn-primary btn-with-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                    </svg>
                    Trigger Rescan
                </button>
            </div>
        `;
    }

    /**
     * Render vulnerability summary with counts
     */
    renderVulnerabilitySummary() {
        const critical = this.scan.CriticalVulnCount || 0;
        const high = this.scan.HighVulnCount || 0;
        const medium = this.scan.MediumVulnCount || 0;
        const low = this.scan.LowVulnCount || 0;
        const total = critical + high + medium + low;

        if (total === 0) {
            return `
                <div class="dashboard-section scan-section">
                    <h2>Vulnerabilities</h2>
                    <div class="empty-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                            <polyline points="22 4 12 14.01 9 11.01"></polyline>
                        </svg>
                        <p>No vulnerabilities found</p>
                    </div>
                </div>
            `;
        }

        return `
            <div class="dashboard-section scan-section">
                <h2>Vulnerability Summary</h2>
                <div class="vuln-summary-grid">
                    ${this.renderVulnerabilitySummaryCard('critical', critical)}
                    ${this.renderVulnerabilitySummaryCard('high', high)}
                    ${this.renderVulnerabilitySummaryCard('medium', medium)}
                    ${this.renderVulnerabilitySummaryCard('low', low)}
                </div>
            </div>
        `;
    }

    /**
     * Render individual vulnerability summary card
     */
    renderVulnerabilitySummaryCard(severity, count) {
        const badge = getSeverityBadge(severity);

        return `
            <div class="vuln-summary-card">
                ${badge}
                <div class="vuln-summary-count">${count.toLocaleString()}</div>
            </div>
        `;
    }

    /**
     * Render vulnerability list grouped by severity
     */
    renderVulnerabilityList() {
        let vulnerabilities = this.scan.Vulnerabilities || [];
        
        // Filter out tolerated vulnerabilities
        const toleratedCVEIds = new Set((this.scan.ToleratedCVEs || []).map(tol => tol.CVEID));
        vulnerabilities = vulnerabilities.filter(vuln => !toleratedCVEIds.has(vuln.CVEID));
        
        if (vulnerabilities.length === 0) {
            return '';
        }

        // Group vulnerabilities by severity using utility function
        // groupBySeverity handles both PascalCase and camelCase field names automatically
        const grouped = groupBySeverity(vulnerabilities);

        return `
            <div class="dashboard-section scan-section">
                <h2>Vulnerability Details</h2>
                <div class="vuln-details-list">
                    ${this.renderVulnerabilityGroup('CRITICAL', grouped.CRITICAL)}
                    ${this.renderVulnerabilityGroup('HIGH', grouped.HIGH)}
                    ${this.renderVulnerabilityGroup('MEDIUM', grouped.MEDIUM)}
                    ${this.renderVulnerabilityGroup('LOW', grouped.LOW)}
                </div>
            </div>
        `;
    }

    /**
     * Render vulnerability group (expandable)
     */
    renderVulnerabilityGroup(severity, vulnerabilities) {
        if (vulnerabilities.length === 0) {
            return '';
        }

        const isExpanded = this.expandedSeverities.has(severity);
        const expandIcon = isExpanded ? '▼' : '▶';

        return `
            <div class="severity-group-container">
                <div data-severity="${severity}" class="severity-group-header">
                    <span class="severity-expand-icon">${expandIcon}</span>
                    ${getSeverityBadge(severity)}
                    <span class="severity-count">${vulnerabilities.length} vulnerabilit${vulnerabilities.length !== 1 ? 'ies' : 'y'}</span>
                </div>
                <div class="severity-group-content ${isExpanded ? 'expanded' : 'collapsed'}">
                    ${vulnerabilities.map(vuln => this.renderVulnerabilityItem(vuln)).join('')}
                </div>
            </div>
        `;
    }

    /**
     * Render individual vulnerability item
     */
    renderVulnerabilityItem(vuln) {
        // API uses PascalCase field names
        const cveId = vuln.CVEID || 'N/A';
        const packageName = vuln.PackageName || 'N/A';
        const installedVersion = vuln.InstalledVersion || 'N/A';
        const fixedVersion = vuln.FixedVersion || '';
        const title = vuln.Title || '';
        const description = vuln.Description || 'No description available';
        const primaryUrl = vuln.PrimaryURL || '';

        const versionDisplay = formatVersions(installedVersion, fixedVersion);

        return `
            <div class="vulnerability-item">
                <div class="vulnerability-header">
                    <div class="vulnerability-cve">
                        ${primaryUrl 
                            ? `<a href="${this.escapeHtml(primaryUrl)}" target="_blank" rel="noopener noreferrer" class="vulnerability-link">${this.escapeHtml(cveId)}</a>`
                            : this.escapeHtml(cveId)
                        }
                    </div>
                    ${title ? `<div class="vulnerability-title">${this.escapeHtml(title)}</div>` : ''}
                </div>
                <div class="vulnerability-details">
                    <div>
                        <span class="detail-label">Package:</span>
                        <span class="detail-value">${this.escapeHtml(packageName)}</span>
                    </div>
                    <div>
                        <span class="detail-label">Version:</span>
                        <span class="detail-value">${this.escapeHtml(versionDisplay)}</span>
                    </div>
                    ${fixedVersion ? `
                        <div>
                            <span class="detail-label">Fixed In:</span>
                            <span class="detail-value fixed-version">${this.escapeHtml(fixedVersion)}</span>
                        </div>
                    ` : ''}
                </div>
                ${description ? `
                    <div class="vulnerability-description">
                        ${this.escapeHtml(description)}
                    </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Render tolerations section
     */
    renderTolerations() {
        const tolerations = this.scan.ToleratedCVEs || [];

        if (tolerations.length === 0) {
            return `
                <div class="dashboard-section">
                    <h2>Applied Tolerations</h2>
                    <div class="empty-state">
                        <p>No tolerations applied to this image</p>
                    </div>
                </div>
            `;
        }

        return `
            <div class="dashboard-section">
                <h2>Applied Tolerations</h2>
                <div class="tolerations-list">
                    ${tolerations.map((tol, index) => this.renderTolerationCard(tol, index)).join('')}
                </div>
            </div>
        `;
    }

    /**
     * Render individual toleration card (expandable)
     */
    renderTolerationCard(toleration, index) {
        const cveId = toleration.CVEID || 'N/A';
        const statement = toleration.Statement || 'No justification provided';
        const toleratedAt = formatDate(toleration.ToleratedAt);
        const expiresAt = toleration.ExpiresAt;
        
        const expirationText = expiresAt ? formatExpirationStatus(expiresAt) : 'No expiration';
        const expirationClass = expiresAt ? getExpirationStatusClass(expiresAt) : 'no-expiration';
        
        // Map expiration class to badge class
        let badgeClass = 'badge';
        if (expirationClass === 'expired') {
            badgeClass = 'badge badge-danger';
        } else if (expirationClass === 'expiring-soon') {
            badgeClass = 'badge badge-warning';
        } else if (expirationClass === 'active') {
            badgeClass = 'badge badge-success';
        }

        const isExpanded = this.expandedTolerations.has(index);
        const expandIcon = isExpanded ? '▼' : '▶';

        // Find mitigated vulnerabilities by matching CVE ID
        const mitigatedVulnerabilities = (this.scan.Vulnerabilities || []).filter(
            vuln => vuln.CVEID === cveId
        );

        return `
            <div class="toleration-card">
                <div data-toleration-index="${index}" class="toleration-card-header">
                    <span class="toleration-expand-icon">${expandIcon}</span>
                    <div class="toleration-card-main">
                        <div class="toleration-header-top">
                            <div class="toleration-cve-id">${this.escapeHtml(cveId)}</div>
                            <div class="toleration-card-meta">
                                <span class="toleration-meta-item">Tolerated: ${toleratedAt}</span>
                                <span class="toleration-meta-item">Expires: ${expiresAt ? formatDate(expiresAt) : 'Never'}</span>
                                <span class="${badgeClass}">${expirationText}</span>
                            </div>
                        </div>
                        <div class="toleration-statement">${this.escapeHtml(statement)}</div>
                    </div>
                </div>
                <div class="toleration-card-content ${isExpanded ? 'expanded' : 'collapsed'}">
                    ${mitigatedVulnerabilities.length > 0 ? `
                        <div class="toleration-mitigated-vulns">
                            <div class="toleration-label">Mitigated Vulnerabilities (${mitigatedVulnerabilities.length})</div>
                            <div class="mitigated-vulns-list">
                                ${mitigatedVulnerabilities.map(vuln => this.renderMitigatedVulnerability(vuln)).join('')}
                            </div>
                        </div>
                    ` : `
                        <div class="toleration-mitigated-vulns">
                            <div class="toleration-label">Mitigated Vulnerabilities</div>
                            <div class="empty-mitigated">No vulnerabilities found for this CVE</div>
                        </div>
                    `}
                </div>
            </div>
        `;
    }

    /**
     * Render mitigated vulnerability item
     */
    renderMitigatedVulnerability(vuln) {
        const packageName = vuln.PackageName || 'N/A';
        const installedVersion = vuln.InstalledVersion || 'N/A';
        const fixedVersion = vuln.FixedVersion || '';
        const title = vuln.Title || '';
        const description = vuln.Description || 'No description available';
        const severity = vuln.Severity || 'UNKNOWN';

        const versionDisplay = formatVersions(installedVersion, fixedVersion);

        return `
            <div class="mitigated-vulnerability-item">
                <div class="mitigated-vuln-header">
                    ${getSeverityBadge(severity)}
                    <div class="mitigated-vuln-info">
                        <div class="mitigated-vuln-title">${title ? this.escapeHtml(title) : 'No title'}</div>
                        <div class="mitigated-vuln-package">${this.escapeHtml(packageName)}</div>
                    </div>
                </div>
                <div class="mitigated-vuln-details">
                    <div>
                        <span class="detail-label">Version:</span>
                        <span class="detail-value">${this.escapeHtml(versionDisplay)}</span>
                    </div>
                    ${fixedVersion ? `
                        <div>
                            <span class="detail-label">Fixed In:</span>
                            <span class="detail-value fixed-version">${this.escapeHtml(fixedVersion)}</span>
                        </div>
                    ` : ''}
                </div>
                ${description ? `
                    <div class="mitigated-vuln-description">
                        ${this.escapeHtml(description)}
                    </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Render error state
     */
    renderError(message) {
        return `
            <div class="scan-detail">
                <div class="error-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                    <h3>Error Loading Scan</h3>
                    <p>${this.escapeHtml(message)}</p>
                    <button class="btn btn-primary" id="back-to-scans">Back to Scans</button>
                </div>
            </div>
        `;
    }

    /**
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Back button
        const backButton = document.getElementById('back-to-scans');
        if (backButton) {
            backButton.addEventListener('click', () => {
                window.router.navigate('/scans');
            });
        }

        // Vulnerability group expand/collapse
        document.querySelectorAll('[data-severity]').forEach(header => {
            header.addEventListener('click', () => {
                const severity = header.dataset.severity;
                const content = header.nextElementSibling;
                const icon = header.querySelector('span:first-child');

                if (this.expandedSeverities.has(severity)) {
                    this.expandedSeverities.delete(severity);
                    content.classList.remove('expanded');
                    content.classList.add('collapsed');
                    icon.textContent = '▶';
                } else {
                    this.expandedSeverities.add(severity);
                    content.classList.remove('collapsed');
                    content.classList.add('expanded');
                    icon.textContent = '▼';
                }
            });
        });

        // Toleration card expand/collapse
        document.querySelectorAll('[data-toleration-index]').forEach(header => {
            header.addEventListener('click', () => {
                const index = parseInt(header.dataset.tolerationIndex, 10);
                const content = header.nextElementSibling;
                const icon = header.querySelector('span:first-child');

                if (this.expandedTolerations.has(index)) {
                    this.expandedTolerations.delete(index);
                    content.classList.remove('expanded');
                    content.classList.add('collapsed');
                    icon.textContent = '▶';
                } else {
                    this.expandedTolerations.add(index);
                    content.classList.remove('collapsed');
                    content.classList.add('expanded');
                    icon.textContent = '▼';
                }
            });
        });

        // Trigger rescan button
        const rescanBtn = document.getElementById('trigger-rescan-btn');
        if (rescanBtn) {
            rescanBtn.addEventListener('click', () => {
                this.handleTriggerRescan();
            });
        }
    }

    /**
     * Handle trigger rescan action
     */
    async handleTriggerRescan() {
        if (!this.scan || !this.digest) {
            this.showNotification('Cannot trigger rescan: scan data not available', 'error');
            return;
        }

        try {
            // Disable button during operation
            const rescanBtn = document.getElementById('trigger-rescan-btn');
            if (rescanBtn) {
                rescanBtn.disabled = true;
                rescanBtn.innerHTML = `
                    <span class="spinner-small"></span>
                    Triggering rescan...
                `;
            }

            // Trigger rescan via API
            const response = await this.apiClient.triggerScan({
                digest: this.digest
            });

            // Show success notification
            const message = response.message || 'Rescan triggered successfully';
            const taskInfo = response.task_id ? ` (Task ID: ${response.task_id})` : '';
            this.showNotification(message + taskInfo, 'success');

            // Re-enable button
            if (rescanBtn) {
                rescanBtn.disabled = false;
                rescanBtn.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="23 4 23 10 17 10"></polyline>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                    </svg>
                    Trigger Rescan
                `;
            }

        } catch (error) {
            console.error('Failed to trigger rescan:', error);
            
            // Handle read-only mode (403 error)
            if (error.status === 403) {
                this.showNotification('Cannot trigger rescan: API is in read-only mode', 'warning');
                
                // Disable button permanently for read-only mode
                const rescanBtn = document.getElementById('trigger-rescan-btn');
                if (rescanBtn) {
                    rescanBtn.disabled = true;
                    rescanBtn.title = 'API is in read-only mode';
                    rescanBtn.innerHTML = `
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="23 4 23 10 17 10"></polyline>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                        </svg>
                        Trigger Rescan (Read-Only Mode)
                    `;
                }
            } else {
                this.showNotification(
                    error.message || 'Failed to trigger rescan',
                    'error'
                );

                // Re-enable button
                const rescanBtn = document.getElementById('trigger-rescan-btn');
                if (rescanBtn) {
                    rescanBtn.disabled = false;
                    rescanBtn.innerHTML = `
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="23 4 23 10 17 10"></polyline>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                        </svg>
                        Trigger Rescan
                    `;
                }
            }
        }
    }

    /**
     * Load data - implements BaseComponent interface
     */
    async loadData() {
        // This method is called by loadAndRender() from BaseComponent
        // For ScanDetail, we need the digest parameter, so we override loadAndRender instead
    }

    /**
     * Load data and render (override to accept digest parameter)
     */
    async loadAndRender(digest) {
        try {
            this.showLoading('Loading scan details...');
            await this.loadScan(digest);
            this.renderAndAttach();
        } catch (error) {
            this.showError(error);
        }
    }
}
