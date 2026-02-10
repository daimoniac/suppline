/**
 * Tag Detail Component
 * Displays scan details for a tag within a repository context.
 * Used when navigating from repositories -> repository detail -> tag.
 * Maintains proper breadcrumb navigation back to the repository.
 */

import { ScanDetailBase } from './scan-detail-base.js';

export class TagDetail extends ScanDetailBase {
    constructor(apiClient) {
        super(apiClient);
        this.repositoryName = null;
    }

    /**
     * Set repository name for breadcrumb navigation
     */
    setRepository(name) {
        this.repositoryName = name;
    }

    /**
     * Render the complete tag detail view with repository context
     */
    render() {
        if (!this.scan) {
            return this.renderError('Digest data not available');
        }

        return `
            <div class="scan-detail">
                <div class="scan-detail-header">
                    <button class="btn btn-secondary btn-sm back-button" id="back-to-repository">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="19" y1="12" x2="5" y2="12"></line>
                            <polyline points="12 19 5 12 12 5"></polyline>
                        </svg>
                        Back to Repository
                    </button>
                    <h1 class="page-title">Digest Details</h1>
                    <p class="page-subtitle">Detailed scan information for this image digest</p>
                </div>

                ${this.renderImageInformation()}
                ${this.renderVulnerabilitySummary()}
                ${this.renderVulnerabilityList()}
                ${this.renderTolerations()}
            </div>
        `;
    }

    /**
     * Attach event listeners after rendering
     */
    attachEventListeners() {
        // Back button - navigate back to repository detail
        const backButton = document.getElementById('back-to-repository');
        if (backButton) {
            backButton.addEventListener('click', () => {
                if (this.repositoryName) {
                    window.router.navigate(`/repositories/${encodeURIComponent(this.repositoryName)}`);
                } else {
                    window.router.navigate('/repositories');
                }
            });
        }

        // Attach common event listeners (expand/collapse, rescan)
        this.attachCommonEventListeners();
    }

    /**
     * Load data - implements BaseComponent interface
     */
    async loadData() {
        // This method is called by loadAndRender() from BaseComponent
        // For TagDetail, we need the digest parameter, so we override loadAndRender instead
    }

    /**
     * Load data and render (override to accept digest parameter)
     */
    async loadAndRender(digest) {
        try {
            this.showLoading('Loading tag details...');
            await this.loadScan(digest);
            this.renderAndAttach();
        } catch (error) {
            this.showError(error);
        }
    }
}
