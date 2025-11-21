/**
 * Integrations Component
 * Displays integration options for public key and Kyverno policy
 */

import { BaseComponent } from './base-component.js';
import { LoadingSpinner, ErrorState } from './common.js';

export class Integrations extends BaseComponent {
    constructor(apiClient) {
        super(apiClient);
        this.selectedIntegration = 'publickey'; // Default selection
        this.integrationData = null;
        this.loading = false;
    }

    /**
     * Load integration data based on selection
     */
    async loadIntegrationData(type) {
        this.loading = true;
        this.selectedIntegration = type;
        
        try {
            if (type === 'publickey') {
                this.integrationData = await this.apiClient.getPublicKey();
            } else if (type === 'kyverno') {
                this.integrationData = await this.apiClient.getKyvernoPolicy();
            }
            this.loading = false;
        } catch (error) {
            this.loading = false;
            throw error;
        }
    }

    /**
     * Render the integrations view
     */
    render() {
        return `
            <div class="integrations-list">
                <div class="integrations-header">
                    <h1 class="page-title">Integrations</h1>
                    <p class="page-subtitle">Export integration configurations for use with external systems</p>
                </div>

                <div class="integration-selector">
                    <label for="integration-type">Select Integration Type:</label>
                    <select id="integration-type" class="integration-dropdown">
                        <option value="publickey" ${this.selectedIntegration === 'publickey' ? 'selected' : ''}>Public Key</option>
                        <option value="kyverno" ${this.selectedIntegration === 'kyverno' ? 'selected' : ''}>Kyverno Policy</option>
                    </select>
                </div>

                <div class="integration-content">
                    ${this.renderIntegrationContent()}
                </div>
            </div>
        `;
    }

    /**
     * Render the content area based on current state
     */
    renderIntegrationContent() {
        if (this.loading) {
            return `
                <div class="loading-state">
                    <div class="spinner"></div>
                    <p>Loading...</p>
                </div>
            `;
        }

        if (!this.integrationData) {
            return `
                <div class="empty-state">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                    <h3>Select an Integration</h3>
                    <p>Choose an integration type from the dropdown above to view its configuration</p>
                </div>
            `;
        }

        const title = this.selectedIntegration === 'publickey' ? 'Cosign Public Key' : 'Kyverno ClusterPolicy';
        const description = this.selectedIntegration === 'publickey' 
            ? 'Use this public key to verify image signatures and attestations created by suppline'
            : 'Apply this Kyverno ClusterPolicy to your Kubernetes cluster to enforce SCAI attestation verification';

        return `
            <div class="integration-details">
                <div class="integration-header">
                    <h3>${this.escapeHtml(title)}</h3>
                    <p>${this.escapeHtml(description)}</p>
                    <div class="integration-actions">
                        <button class="btn btn-primary" id="copy-integration-btn">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                            </svg>
                            Copy to Clipboard
                        </button>
                        <button class="btn btn-secondary" id="download-integration-btn">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="7 10 12 15 17 10"></polyline>
                                <line x1="12" y1="15" x2="12" y2="3"></line>
                            </svg>
                            Download
                        </button>
                    </div>
                </div>
                <div class="integration-code">
                    <pre><code id="integration-code-content">${this.escapeHtml(this.integrationData)}</code></pre>
                </div>
            </div>
        `;
    }

    /**
     * Attach event listeners
     */
    attachEventListeners() {
        // Dropdown change handler
        const dropdown = document.getElementById('integration-type');
        if (dropdown) {
            dropdown.addEventListener('change', async (e) => {
                const type = e.target.value;
                await this.handleIntegrationChange(type);
            });
        }

        // Copy button handler
        const copyBtn = document.getElementById('copy-integration-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => this.handleCopy());
        }

        // Download button handler
        const downloadBtn = document.getElementById('download-integration-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => this.handleDownload());
        }
    }

    /**
     * Handle integration type change
     */
    async handleIntegrationChange(type) {
        try {
            // Update the content area to show loading
            const contentArea = document.querySelector('.integration-content');
            if (contentArea) {
                contentArea.innerHTML = this.renderIntegrationContent();
            }

            await this.loadIntegrationData(type);
            
            // Re-render the content area
            if (contentArea) {
                contentArea.innerHTML = this.renderIntegrationContent();
                // Re-attach event listeners for the new content
                this.attachEventListeners();
            }
        } catch (error) {
            console.error('Failed to load integration data:', error);
            this.showNotification('Failed to load integration data: ' + error.message, 'error');
            
            const contentArea = document.querySelector('.integration-content');
            if (contentArea) {
                contentArea.innerHTML = `
                    <div class="error-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="15" y1="9" x2="9" y2="15"></line>
                            <line x1="9" y1="9" x2="15" y2="15"></line>
                        </svg>
                        <h3>Error Loading Integration</h3>
                        <p>${this.escapeHtml(error.message || 'Failed to load integration data')}</p>
                    </div>
                `;
            }
        }
    }

    /**
     * Handle copy to clipboard
     */
    async handleCopy() {
        if (!this.integrationData) return;

        try {
            await navigator.clipboard.writeText(this.integrationData);
            this.showNotification('Copied to clipboard', 'success');
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            this.showNotification('Failed to copy to clipboard', 'error');
        }
    }

    /**
     * Handle download
     */
    handleDownload() {
        if (!this.integrationData) return;

        const filename = this.selectedIntegration === 'publickey' 
            ? 'suppline-public-key.pem' 
            : 'suppline-kyverno-policy.yaml';
        
        const blob = new Blob([this.integrationData], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showNotification(`Downloaded ${filename}`, 'success');
    }
}
