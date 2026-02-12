/**
 * Scan Detail Base Component
 * Shared logic for displaying scan details, used by both ScanDetail and ArtifactDetail views.
 * This component handles rendering vulnerabilities, tolerations, and attestation info.
 */

import { BaseComponent } from './base-component.js';
import { escapeHtml } from '../utils/security.js';
import { formatDate, formatRelativeTime, formatExpirationStatus, getExpirationStatusClass } from '../utils/date.js';
import { 
    getSeverityBadge, 
    truncateDigest,
    formatVersions,
    groupBySeverity
} from '../utils/severity.js';

export class ScanDetailBase extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.scan = null;
        this.digest = null;
        this.expandedSeverities = new Set();
        this.expandedTolerations = new Set();
    }

    /**
     * Load scan details from API
     * @param {string} digest - Image digest
     */
    async loadScan(digest) {
        try {
            this.digest = digest;
            this.scan = await this.apiClient.getScanByDigest(digest);
            return this.scan;
        } catch (error) {
            console.error('Failed to load scan details:', error);
            throw error;
        }
    }

    /**
     * Render image information section
     */
    renderImageInformation() {
        const statusClass = this.scan.PolicyPassed ? 'status-success' : 'status-danger';
        const statusText = this.scan.PolicyPassed ? 'Passed' : 'Failed';
        const scanTime = formatDate(this.scan.CreatedAt);
        const relativeTime = formatRelativeTime(this.scan.CreatedAt);

        // Check if we have multiple tags for this digest
        const hasTags = this.scan.Tags && this.scan.Tags.length > 0;
        const tagDisplay = hasTags ? this.renderTagsList() : escapeHtml(this.scan.Tag || 'N/A');

        return `
            <div class="dashboard-section scan-section">
                <h2>Image Information</h2>
                <div class="info-grid">
                    <div>
                        <div class="info-label">Repository</div>
                        <div class="info-value">
                            <span class="repository-link-cell" data-repository="${escapeHtml(this.scan.Repository || 'N/A')}">${escapeHtml(this.scan.Repository || 'N/A')}</span>
                        </div>
                    </div>
                    <div>
                        <div class="info-label">${hasTags && this.scan.Tags.length > 1 ? 'Tags' : 'Tag'}</div>
                        <div class="info-value">${tagDisplay}</div>
                    </div>
                    <div>
                        <div class="info-label">Digest</div>
                        <div class="digest-cell" title="${escapeHtml(this.scan.Digest)}">${escapeHtml(truncateDigest(this.scan.Digest))}</div>
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
                        </div>
                    </div>
                </div>
                ${this.renderRescanButton()}
            </div>
        `;
    }

    /**
     * Render list of tags pointing to this digest
     */
    renderTagsList() {
        if (!this.scan.Tags || this.scan.Tags.length === 0) {
            return escapeHtml(this.scan.Tag || 'N/A');
        }

        // Group tags by repository
        const tagsByRepo = {};
        this.scan.Tags.forEach(tagRef => {
            if (!tagsByRepo[tagRef.Repository]) {
                tagsByRepo[tagRef.Repository] = [];
            }
            tagsByRepo[tagRef.Repository].push(tagRef.Tag);
        });

        // Render tags grouped by repository
        return Object.entries(tagsByRepo).map(([repo, tags]) => {
            const tagList = tags.map(tag => `<code class="tag-badge">${escapeHtml(tag)}</code>`).join(' ');
            if (Object.keys(tagsByRepo).length > 1) {
                // Multiple repositories - show repo name
                return `<div class="tag-group"><strong>${escapeHtml(repo)}:</strong> ${tagList}</div>`;
            } else {
                // Single repository - just show tags
                return `<div class="tag-group">${tagList}</div>`;
            }
        }).join('');
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
        
        const toleratedCVEIds = new Set((this.scan.ToleratedCVEs || []).map(tol => tol.CVEID));
        vulnerabilities = vulnerabilities.filter(vuln => !toleratedCVEIds.has(vuln.CVEID));
        
        if (vulnerabilities.length === 0) {
            return '';
        }

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
                            ? `<a href="${escapeHtml(primaryUrl)}" target="_blank" rel="noopener noreferrer" class="vulnerability-link">${escapeHtml(cveId)}</a>`
                            : escapeHtml(cveId)
                        }
                    </div>
                    ${title ? `<div class="vulnerability-title">${escapeHtml(title)}</div>` : ''}
                </div>
                <div class="vulnerability-details">
                    <div>
                        <span class="detail-label">Package:</span>
                        <span class="detail-value">${escapeHtml(packageName)}</span>
                    </div>
                    <div>
                        <span class="detail-label">Version:</span>
                        <span class="detail-value">${escapeHtml(versionDisplay)}</span>
                    </div>
                    ${fixedVersion ? `
                        <div>
                            <span class="detail-label">Fixed In:</span>
                            <span class="detail-value fixed-version">${escapeHtml(fixedVersion)}</span>
                        </div>
                    ` : ''}
                </div>
                ${description ? `
                    <div class="vulnerability-description">
                        ${escapeHtml(description)}
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

        const mitigatedVulnerabilities = (this.scan.Vulnerabilities || []).filter(
            vuln => vuln.CVEID === cveId
        );

        return `
            <div class="toleration-card">
                <div data-toleration-index="${index}" class="toleration-card-header">
                    <span class="toleration-expand-icon">${expandIcon}</span>
                    <div class="toleration-card-main">
                        <div class="toleration-header-top">
                            <div class="toleration-cve-id">${escapeHtml(cveId)}</div>
                            <div class="toleration-card-meta">
                                <span class="toleration-meta-item">Tolerated: ${toleratedAt}</span>
                                <span class="toleration-meta-item">Expires: ${expiresAt ? formatDate(expiresAt) : 'Never'}</span>
                                <span class="${badgeClass}">${expirationText}</span>
                            </div>
                        </div>
                        <div class="toleration-statement">${escapeHtml(statement)}</div>
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
                        <div class="mitigated-vuln-title">${title ? escapeHtml(title) : 'No title'}</div>
                        <div class="mitigated-vuln-package">${escapeHtml(packageName)}</div>
                    </div>
                </div>
                <div class="mitigated-vuln-details">
                    <div>
                        <span class="detail-label">Version:</span>
                        <span class="detail-value">${escapeHtml(versionDisplay)}</span>
                    </div>
                    ${fixedVersion ? `
                        <div>
                            <span class="detail-label">Fixed In:</span>
                            <span class="detail-value fixed-version">${escapeHtml(fixedVersion)}</span>
                        </div>
                    ` : ''}
                </div>
                ${description ? `
                    <div class="mitigated-vuln-description">
                        ${escapeHtml(description)}
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
                    <p>${escapeHtml(message)}</p>
                </div>
            </div>
        `;
    }

    /**
     * Attach common event listeners for expand/collapse and rescan
     */
    attachCommonEventListeners() {
        // Repository link click handler
        document.querySelectorAll('.repository-link-cell').forEach(link => {
            link.addEventListener('click', (e) => {
                e.stopPropagation();
                const repository = link.dataset.repository;
                if (repository && repository !== 'N/A') {
                    window.router.navigate(`/repositories/${encodeURIComponent(repository)}`);
                }
            });
        });

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
            const rescanBtn = document.getElementById('trigger-rescan-btn');
            if (rescanBtn) {
                rescanBtn.disabled = true;
                rescanBtn.innerHTML = `
                    <span class="spinner-small"></span>
                    Triggering rescan...
                `;
            }

            const response = await this.apiClient.triggerScan({
                digest: this.digest
            });

            const message = response.message || 'Rescan triggered successfully';
            const taskInfo = response.task_id ? ` (Task ID: ${response.task_id})` : '';
            this.showNotification(message + taskInfo, 'success');

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
            
            if (error.status === 403) {
                this.showNotification('Cannot trigger rescan: API is in read-only mode', 'warning');
                
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
        // Override in subclasses
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
