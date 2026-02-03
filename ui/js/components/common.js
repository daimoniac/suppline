/**
 * Common UI Components
 * Shared components for notifications, loading states, modals, badges, and error handling
 */

import { escapeHtml } from '../utils/security.js';

/**
 * Notification/Toast System
 * Displays temporary notification messages to the user
 */
export class NotificationManager {
    constructor() {
        this.container = null;
        this.notifications = new Map();
        this.nextId = 1;
        this.init();
    }

    /**
     * Initialize notification container
     */
    init() {
        // Create container if it doesn't exist
        if (!document.getElementById('notifications')) {
            this.container = document.createElement('div');
            this.container.id = 'notifications';
            document.body.appendChild(this.container);
        } else {
            this.container = document.getElementById('notifications');
        }
    }

    /**
     * Show a notification
     * @param {string} message - Message to display
     * @param {string} type - Type: 'success', 'error', 'warning', 'info'
     * @param {number} duration - Duration in ms (0 = no auto-dismiss)
     * @returns {number} Notification ID
     */
    show(message, type = 'info', duration = 5000) {
        const id = this.nextId++;
        const notification = this.createNotification(id, message, type);
        
        this.container.appendChild(notification);
        this.notifications.set(id, notification);

        // Auto-dismiss after duration
        if (duration > 0) {
            setTimeout(() => this.dismiss(id), duration);
        }

        return id;
    }

    /**
     * Create notification element
     */
    createNotification(id, message, type) {
        const notification = document.createElement('div');
        notification.className = `notification-toast notification-${type}`;
        notification.dataset.id = id;

        const icon = this.getIcon(type);
        
        notification.innerHTML = `
            ${icon}
            <span>${escapeHtml(message)}</span>
            <button class="notification-close" aria-label="Close">&times;</button>
        `;

        // Add close button handler
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => this.dismiss(id));

        return notification;
    }

    /**
     * Get icon SVG for notification type
     */
    getIcon(type) {
        const icons = {
            success: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>`,
            error: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>`,
            warning: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>`,
            info: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="16" x2="12" y2="12"></line>
                <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>`
        };
        return icons[type] || icons.info;
    }

    /**
     * Dismiss a notification
     */
    dismiss(id) {
        const notification = this.notifications.get(id);
        if (notification) {
            notification.classList.add('notification-fade-out');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
                this.notifications.delete(id);
            }, 300);
        }
    }

    /**
     * Dismiss all notifications
     */
    dismissAll() {
        this.notifications.forEach((_, id) => this.dismiss(id));
    }
}

/**
 * Loading Spinner Component
 * Displays loading state with optional message
 */
export class LoadingSpinner {
    /**
     * Create a loading spinner element
     * @param {string} message - Optional loading message
     * @param {boolean} small - Use small spinner variant
     * @returns {HTMLElement}
     */
    static create(message = 'Loading...', small = false) {
        const container = document.createElement('div');
        container.className = 'loading-state';
        
        const spinnerClass = small ? 'spinner-small' : 'spinner';
        
        container.innerHTML = `
            <div class="${spinnerClass}"></div>
            ${message ? `<p>${escapeHtml(message)}</p>` : ''}
        `;
        
        return container;
    }

    /**
     * Create inline spinner (for buttons, etc.)
     * @returns {HTMLElement}
     */
    static createInline() {
        const spinner = document.createElement('span');
        spinner.className = 'spinner-small';
        return spinner;
    }

    /**
     * Show loading state in container
     * @param {HTMLElement} container - Container element
     * @param {string} message - Loading message
     */
    static show(container, message = 'Loading...') {
        container.innerHTML = '';
        container.appendChild(this.create(message));
    }


}

/**
 * Modal Dialog Component
 * Displays modal dialogs for confirmations and alerts
 */
export class Modal {
    constructor(options = {}) {
        this.title = options.title || '';
        this.content = options.content || '';
        this.confirmText = options.confirmText || 'Confirm';
        this.cancelText = options.cancelText || 'Cancel';
        this.onConfirm = options.onConfirm || (() => {});
        this.onCancel = options.onCancel || (() => {});
        this.showCancel = options.showCancel !== false;
        this.element = null;
    }

    /**
     * Show the modal
     */
    show() {
        this.element = this.create();
        document.body.appendChild(this.element);
        
        // Focus first button
        const firstButton = this.element.querySelector('button');
        if (firstButton) {
            firstButton.focus();
        }

        // Handle escape key
        this.handleEscape = (e) => {
            if (e.key === 'Escape') {
                this.hide();
                this.onCancel();
            }
        };
        document.addEventListener('keydown', this.handleEscape);
    }

    /**
     * Hide the modal
     */
    hide() {
        if (this.element && this.element.parentNode) {
            this.element.parentNode.removeChild(this.element);
        }
        document.removeEventListener('keydown', this.handleEscape);
    }

    /**
     * Create modal element
     */
    create() {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        
        overlay.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-header">
                    <h3>${escapeHtml(this.title)}</h3>
                </div>
                <div class="modal-body">
                    ${typeof this.content === 'string' ? `<p>${escapeHtml(this.content)}</p>` : ''}
                </div>
                <div class="modal-footer">
                    ${this.showCancel ? `<button class="btn btn-secondary modal-cancel">${escapeHtml(this.cancelText)}</button>` : ''}
                    <button class="btn btn-primary modal-confirm">${escapeHtml(this.confirmText)}</button>
                </div>
            </div>
        `;

        // If content is an element, replace the paragraph
        if (typeof this.content !== 'string') {
            const body = overlay.querySelector('.modal-body');
            body.innerHTML = '';
            body.appendChild(this.content);
        }

        // Add event listeners
        const confirmBtn = overlay.querySelector('.modal-confirm');
        confirmBtn.addEventListener('click', () => {
            this.onConfirm();
            this.hide();
        });

        if (this.showCancel) {
            const cancelBtn = overlay.querySelector('.modal-cancel');
            cancelBtn.addEventListener('click', () => {
                this.onCancel();
                this.hide();
            });
        }

        // Close on overlay click
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                this.onCancel();
                this.hide();
            }
        });

        return overlay;
    }

    /**
     * Static method to show a confirmation dialog
     * @param {string} title - Dialog title
     * @param {string} message - Dialog message
     * @returns {Promise<boolean>} Resolves to true if confirmed, false if cancelled
     */
    static confirm(title, message) {
        return new Promise((resolve) => {
            const modal = new Modal({
                title,
                content: message,
                confirmText: 'Confirm',
                cancelText: 'Cancel',
                onConfirm: () => resolve(true),
                onCancel: () => resolve(false)
            });
            modal.show();
        });
    }

    /**
     * Static method to show an alert dialog
     * @param {string} title - Dialog title
     * @param {string} message - Dialog message
     * @returns {Promise<void>}
     */
    static alert(title, message) {
        return new Promise((resolve) => {
            const modal = new Modal({
                title,
                content: message,
                confirmText: 'OK',
                showCancel: false,
                onConfirm: () => resolve()
            });
            modal.show();
        });
    }
}

/**
 * Badge Component
 * Creates styled badge elements for status indicators
 */
export class Badge {
    /**
     * Create a status badge
     * @param {string} text - Badge text
     * @param {string} type - Badge type: 'success', 'danger', 'warning', 'info'
     * @returns {string} HTML string
     */
    static create(text, type = 'info') {
        const typeClass = type === 'info' ? 'status-info' : `badge-${type}`;
        return `<span class="badge ${typeClass}">${escapeHtml(text)}</span>`;
    }

    /**
     * Create a severity badge
     * @param {string} severity - Severity level: 'critical', 'high', 'medium', 'low'
     * @param {number} count - Optional count to display
     * @returns {string} HTML string
     */
    static severity(severity, count = null) {
        const text = count !== null ? `${severity.toUpperCase()}: ${count}` : severity.toUpperCase();
        return `<span class="badge badge-${severity.toLowerCase()}">${text}</span>`;
    }

    /**
     * Create a vulnerability count badge
     * @param {string} severity - Severity level
     * @param {number} count - Vulnerability count
     * @returns {string} HTML string
     */
    static vulnerabilityCount(severity, count) {
        return `<span class="vuln-badge vuln-badge-${severity.toLowerCase()}">${count}</span>`;
    }

    /**
     * Create a status badge (passed/failed)
     * @param {boolean} passed - Whether status is passed
     * @returns {string} HTML string
     */
    static status(passed) {
        const type = passed ? 'success' : 'danger';
        const text = passed ? 'Passed' : 'Failed';
        return `<span class="status-badge status-${type}">${text}</span>`;
    }


}

/**
 * Error State Component
 * Displays error states with helpful messages
 */
export class ErrorState {
    /**
     * Create an error state element
     * @param {string} title - Error title
     * @param {string} message - Error message
     * @param {Function} onRetry - Optional retry callback
     * @returns {HTMLElement}
     */
    static create(title = 'Error', message = 'Something went wrong', onRetry = null) {
        const container = document.createElement('div');
        container.className = 'error-state';
        
        container.innerHTML = `
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
            <h3>${escapeHtml(title)}</h3>
            <p>${escapeHtml(message)}</p>
            ${onRetry ? '<button class="btn btn-primary retry-btn">Try Again</button>' : ''}
        `;

        if (onRetry) {
            const retryBtn = container.querySelector('.retry-btn');
            retryBtn.addEventListener('click', onRetry);
        }

        return container;
    }

    /**
     * Show error state in container
     * @param {HTMLElement} container - Container element
     * @param {string} title - Error title
     * @param {string} message - Error message
     * @param {Function} onRetry - Optional retry callback
     */
    static show(container, title, message, onRetry = null) {
        container.innerHTML = '';
        container.appendChild(this.create(title, message, onRetry));
    }
}

/**
 * Empty State Component
 * Displays empty states when no data is available
 */
export class EmptyState {
    /**
     * Create an empty state element
     * @param {string} title - Empty state title
     * @param {string} message - Empty state message
     * @param {string} actionText - Optional action button text
     * @param {Function} onAction - Optional action callback
     * @returns {HTMLElement}
     */
    static create(title = 'No Data', message = 'No items to display', actionText = null, onAction = null) {
        const container = document.createElement('div');
        container.className = 'empty-state';
        
        container.innerHTML = `
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <h3>${escapeHtml(title)}</h3>
            <p>${escapeHtml(message)}</p>
            ${actionText && onAction ? `<button class="btn btn-primary action-btn">${escapeHtml(actionText)}</button>` : ''}
        `;

        if (actionText && onAction) {
            const actionBtn = container.querySelector('.action-btn');
            actionBtn.addEventListener('click', onAction);
        }

        return container;
    }

    /**
     * Show empty state in container
     * @param {HTMLElement} container - Container element
     * @param {string} title - Empty state title
     * @param {string} message - Empty state message
     */
    static show(container, title, message) {
        container.innerHTML = '';
        container.appendChild(this.create(title, message));
    }
}

/**
 * Skeleton Loading Component
 * Displays skeleton screens during data loading
 */
export class SkeletonLoader {
    /**
     * Create a skeleton table
     * @param {number} rows - Number of skeleton rows
     * @param {number} columns - Number of columns
     * @returns {HTMLElement}
     */
    static createTable(rows = 5, columns = 6) {
        const table = document.createElement('table');
        table.className = 'skeleton-table';
        
        // Create header
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        for (let i = 0; i < columns; i++) {
            const th = document.createElement('th');
            th.innerHTML = '<div class="skeleton-box skeleton-line skeleton-line-80"></div>';
            headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        // Create body
        const tbody = document.createElement('tbody');
        for (let i = 0; i < rows; i++) {
            const row = document.createElement('tr');
            for (let j = 0; j < columns; j++) {
                const td = document.createElement('td');
                const width = 60 + Math.random() * 30; // Random width between 60-90%
                const skeletonDiv = document.createElement('div');
                skeletonDiv.className = 'skeleton-box skeleton-line';
                skeletonDiv.style.setProperty('--bar-width', `${width}%`);
                td.appendChild(skeletonDiv);
                row.appendChild(td);
            }
            tbody.appendChild(row);
        }
        table.appendChild(tbody);
        
        return table;
    }

    /**
     * Create skeleton cards
     * @param {number} count - Number of skeleton cards
     * @returns {HTMLElement}
     */
    static createCards(count = 4) {
        const container = document.createElement('div');
        container.className = 'summary-cards';
        
        for (let i = 0; i < count; i++) {
            const card = document.createElement('div');
            card.className = 'summary-card';
            card.innerHTML = `
                <div class="skeleton-box skeleton-icon"></div>
                <div class="skeleton-card-content">
                    <div class="skeleton-box skeleton-line skeleton-line-60 skeleton-line-large"></div>
                    <div class="skeleton-box skeleton-line skeleton-line-80"></div>
                </div>
            `;
            container.appendChild(card);
        }
        
        return container;
    }

    /**
     * Create skeleton text lines
     * @param {number} lines - Number of lines
     * @returns {HTMLElement}
     */
    static createText(lines = 3) {
        const container = document.createElement('div');
        container.className = 'skeleton-text';
        
        for (let i = 0; i < lines; i++) {
            const width = i === lines - 1 ? 60 : 100; // Last line shorter
            const line = document.createElement('div');
            line.className = 'skeleton-box skeleton-line';
            if (i === lines - 1) {
                line.classList.add('skeleton-line-short');
            }
            container.appendChild(line);
        }
        
        return container;
    }
}

// Add skeleton styles dynamically if not already present
if (!document.getElementById('skeleton-styles')) {
    const style = document.createElement('style');
    style.id = 'skeleton-styles';
    style.textContent = `
        .skeleton-box {
            background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
            background-size: 200% 100%;
            animation: skeleton-loading 1.5s ease-in-out infinite;
            border-radius: 4px;
        }
        
        @keyframes skeleton-loading {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }
        
        .skeleton-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .skeleton-table th,
        .skeleton-table td {
            padding: 0.75rem 1rem;
        }
        
        .skeleton-text {
            padding: 1rem 0;
        }
    `;
    document.head.appendChild(style);
}

// Export singleton instance of NotificationManager
export const notifications = new NotificationManager();
