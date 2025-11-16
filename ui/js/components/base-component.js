/**
 * Base Component Class
 * Provides common functionality for all view components
 */

import { LoadingSpinner, ErrorState, notifications } from './common.js';

export class BaseComponent {
    constructor(apiClient) {
        this.apiClient = apiClient;
    }

    /**
     * Escape HTML to prevent XSS
     * Centralized implementation used by all components
     */
    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    /**
     * Show loading state in content container
     */
    showLoading(message = 'Loading...') {
        const container = document.getElementById('content');
        if (container) {
            LoadingSpinner.show(container, message);
        }
    }

    /**
     * Show error state in content container
     */
    showError(error) {
        const container = document.getElementById('content');
        if (container) {
            const message = error.message || 'An unexpected error occurred';
            ErrorState.show(container, 'Error', message, () => location.reload());
        }
    }

    /**
     * Render and attach event listeners
     * Standard pattern for all components
     */
    renderAndAttach() {
        const container = document.getElementById('content');
        if (container) {
            container.innerHTML = this.render();
            this.attachEventListeners();
        }
    }

    /**
     * Load data and render
     * Standard pattern for all components
     */
    async loadAndRender() {
        try {
            this.showLoading();
            await this.loadData();
            this.renderAndAttach();
        } catch (error) {
            this.showError(error);
        }
    }

    /**
     * Show notification toast
     * Uses centralized notification system
     */
    showNotification(message, type = 'info') {
        notifications.show(message, type);
    }

    /**
     * Render method - must be implemented by subclasses
     */
    render() {
        throw new Error('render() must be implemented by subclass');
    }

    /**
     * Attach event listeners - must be implemented by subclasses
     */
    attachEventListeners() {
        throw new Error('attachEventListeners() must be implemented by subclass');
    }

    /**
     * Load data - should be implemented by subclasses if needed
     */
    async loadData() {
        // Default implementation does nothing
    }
}
