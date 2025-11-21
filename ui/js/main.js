/**
 * Main Application Entry Point
 * Initializes the suppline-ui dashboard application
 */

import { Router } from './router.js';
import { APIClient, APIError } from './api.js';
import { AuthManager } from './auth.js';
import { Dashboard } from './components/dashboard.js';
import { ScansList } from './components/scans.js';
import { ScanDetail } from './components/scan-detail.js';
import { Tolerations } from './components/tolerations.js';
import { Vulnerabilities } from './components/vulnerabilities.js';
import { FailedImages } from './components/failed-images.js';
import { Integrations } from './components/integrations.js';

/**
 * Application class - manages the entire application lifecycle
 */
class Application {
    constructor() {
        this.config = null;
        this.apiClient = null;
        this.authManager = null;
        this.router = null;
        this.currentView = null;
    }

    /**
     * Initialize the application
     */
    async init() {
        try {
            // Load configuration first
            await this.loadConfiguration();

            // Initialize API client
            this.apiClient = new APIClient(this.config.apiBaseURL);

            // Initialize authentication manager
            this.authManager = new AuthManager(this.apiClient);
            this.authManager.init();

            // Setup authentication UI (modal is already in HTML)
            this.setupAuthUI();

            // Initialize router
            this.router = new Router();
            window.router = this.router; // Make router globally accessible

            // Register routes
            this.registerRoutes();

            // Setup global error handlers
            this.setupErrorHandlers();

            // Check authentication and show modal if needed
            if (!this.authManager.isAuthenticated()) {
                this.showAuthModal();
            }

            // Listen for auth state changes
            this.authManager.onAuthChange((isAuthenticated) => {
                if (isAuthenticated) {
                    // Re-render current route after authentication
                    this.router.handleRoute();
                }
            });

            // Initialize router and handle initial route
            this.router.init();

            console.log('Application initialized successfully');
        } catch (error) {
            console.error('Failed to initialize application:', error);
            this.showFatalError(error);
        }
    }

    /**
     * Load configuration from /config.json endpoint
     */
    async loadConfiguration() {
        try {
            // The config is loaded via script tag in index.html
            // Check if it's already available
            if (window.APP_CONFIG) {
                this.config = window.APP_CONFIG;
                console.log('Configuration loaded:', this.config);
                return;
            }

            // Fallback: try to fetch config.json if not already loaded
            const response = await fetch('/config.json');
            if (!response.ok) {
                throw new Error('Failed to load configuration');
            }

            // Parse JSON configuration safely
            const configData = await response.json();
            
            if (configData && typeof configData === 'object') {
                this.config = configData;
                window.APP_CONFIG = configData;
                console.log('Configuration loaded:', this.config);
            } else {
                throw new Error('Invalid configuration format');
            }
        } catch (error) {
            console.error('Configuration loading error:', error);
            // Use default configuration as fallback
            this.config = {
                apiBaseURL: window.location.origin
            };
            console.warn('Using default configuration:', this.config);
        }
    }

    /**
     * Register all application routes
     */
    registerRoutes() {
        // Dashboard (home)
        this.router.addRoute('/', async () => {
            await this.renderDashboard();
        });

        // Scans list
        this.router.addRoute('/scans', async (params, queryParams) => {
            await this.renderScansList(queryParams);
        });

        // Scan detail
        this.router.addRoute('/scans/:digest', async (params) => {
            await this.renderScanDetail(params.digest);
        });

        // Failed images
        this.router.addRoute('/failed', async () => {
            await this.renderFailedImages();
        });

        // Vulnerabilities search
        this.router.addRoute('/vulnerabilities', async (params, queryParams) => {
            await this.renderVulnerabilities(queryParams);
        });

        // Tolerations list
        this.router.addRoute('/tolerations', async (params, queryParams) => {
            await this.renderTolerations(queryParams);
        });

        // Expiring tolerations
        this.router.addRoute('/tolerations/expiring', async () => {
            await this.renderExpiringTolerations();
        });

        // Integrations
        this.router.addRoute('/integrations', async (params, queryParams) => {
            await this.renderIntegrations(queryParams);
        });

        // 404 handler
        this.router.setNotFoundHandler(() => {
            this.render404();
        });
    }

    /**
     * Render dashboard view
     */
    async renderDashboard() {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            const dashboard = new Dashboard(this.apiClient);
            await dashboard.loadData();
            
            const content = document.getElementById('content');
            content.innerHTML = dashboard.render();
            dashboard.attachEventListeners();
            
            this.currentView = dashboard;
            this.updateActiveNavLink('/');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render scans list view
     */
    async renderScansList(queryParams = {}) {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            const scansList = new ScansList(this.apiClient);
            
            // Apply filters from query parameters
            if (queryParams.repository) {
                scansList.setFilters({ repository: decodeURIComponent(queryParams.repository) });
            }
            if (queryParams.policy_passed !== undefined) {
                const policyPassed = queryParams.policy_passed === 'true' ? true : 
                                    queryParams.policy_passed === 'false' ? false : null;
                scansList.setFilters({ policy_passed: policyPassed });
            }
            
            await scansList.loadScans();
            
            const content = document.getElementById('content');
            content.innerHTML = scansList.render();
            scansList.attachEventListeners();
            
            this.currentView = scansList;
            this.updateActiveNavLink('/scans');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render scan detail view
     */
    async renderScanDetail(digest) {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            // Decode the digest from URL encoding
            const decodedDigest = decodeURIComponent(digest);
            const scanDetail = new ScanDetail(this.apiClient);
            await scanDetail.loadScan(decodedDigest);
            
            const content = document.getElementById('content');
            content.innerHTML = scanDetail.render();
            scanDetail.attachEventListeners();
            
            this.currentView = scanDetail;
            this.updateActiveNavLink('/scans');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render failed images view
     */
    async renderFailedImages() {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            const failedImages = new FailedImages(this.apiClient);
            await failedImages.loadScans();
            
            const content = document.getElementById('content');
            content.innerHTML = failedImages.render();
            failedImages.attachEventListeners();
            
            this.currentView = failedImages;
            this.updateActiveNavLink('/failed');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render vulnerabilities view
     */
    async renderVulnerabilities(queryParams = {}) {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            const vulnerabilities = new Vulnerabilities(this.apiClient);
            
            // Apply filters from query parameters
            if (queryParams.cve_id) {
                vulnerabilities.setFilters({ cve_id: decodeURIComponent(queryParams.cve_id) });
            }
            if (queryParams.severity) {
                vulnerabilities.setFilters({ severity: decodeURIComponent(queryParams.severity) });
            }
            if (queryParams.package_name) {
                vulnerabilities.setFilters({ package_name: decodeURIComponent(queryParams.package_name) });
            }
            if (queryParams.repository) {
                vulnerabilities.setFilters({ repository: decodeURIComponent(queryParams.repository) });
            }
            
            // Load all vulnerabilities by default
            await vulnerabilities.loadVulnerabilities();
            
            const content = document.getElementById('content');
            content.innerHTML = vulnerabilities.render();
            vulnerabilities.attachEventListeners();
            
            this.currentView = vulnerabilities;
            this.updateActiveNavLink('/vulnerabilities');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render tolerations view
     */
    async renderTolerations(queryParams = {}) {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            const tolerations = new Tolerations(this.apiClient);
            
            // Apply filters from query parameters
            if (queryParams.cve_id) {
                tolerations.setFilters({ cve_id: decodeURIComponent(queryParams.cve_id) });
            }
            if (queryParams.repository) {
                tolerations.setFilters({ repository: decodeURIComponent(queryParams.repository) });
            }
            if (queryParams.expiration_status) {
                tolerations.setFilters({ expiration_status: decodeURIComponent(queryParams.expiration_status) });
            }
            
            await tolerations.loadTolerations();
            
            const content = document.getElementById('content');
            content.innerHTML = tolerations.render();
            tolerations.attachEventListeners();
            
            this.currentView = tolerations;
            this.updateActiveNavLink('/tolerations');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render expiring tolerations view
     */
    async renderExpiringTolerations() {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            const tolerations = new Tolerations(this.apiClient);
            await tolerations.loadTolerations({ expiring_soon: true });
            
            const content = document.getElementById('content');
            content.innerHTML = tolerations.renderExpiringView();
            tolerations.attachEventListeners();
            
            this.currentView = tolerations;
            this.updateActiveNavLink('/tolerations');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render integrations view
     */
    async renderIntegrations(queryParams = {}) {
        if (!this.authManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        try {
            this.showLoading();
            const integrations = new Integrations(this.apiClient);
            
            // Load default integration (public key) or from query params
            const integrationType = queryParams.type || 'publickey';
            await integrations.loadIntegrationData(integrationType);
            
            const content = document.getElementById('content');
            content.innerHTML = integrations.render();
            integrations.attachEventListeners();
            
            this.currentView = integrations;
            this.updateActiveNavLink('/integrations');
        } catch (error) {
            this.handleViewError(error);
        }
    }

    /**
     * Render 404 not found page
     */
    render404() {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="error-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <h3>Page Not Found</h3>
                <p>The page you're looking for doesn't exist.</p>
                <button class="btn btn-primary" id="go-home-btn">Go to Dashboard</button>
            </div>
        `;
        this.updateActiveNavLink(null);
        
        // Attach event listener for the button
        setTimeout(() => {
            const homeBtn = document.getElementById('go-home-btn');
            if (homeBtn) {
                homeBtn.addEventListener('click', () => window.router.navigate('/'));
            }
        }, 0);
    }

    /**
     * Show loading state
     */
    showLoading() {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="loading-state">
                <div class="spinner"></div>
                <p>Loading...</p>
            </div>
        `;
    }

    /**
     * Show authentication required message
     */
    showAuthRequired() {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
                <h3>Authentication Required</h3>
                <p>Please authenticate to access the dashboard.</p>
            </div>
        `;
    }

    /**
     * Handle view rendering errors
     */
    handleViewError(error) {
        console.error('View rendering error:', error);

        // Handle 401 errors by showing auth modal
        if (error instanceof APIError && error.status === 401) {
            this.authManager.clearAPIKey();
            this.showAuthModal();
            return;
        }

        // Show error state
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="error-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <h3>Error Loading View</h3>
                <p>${this.escapeHtml(error.message || 'An unexpected error occurred')}</p>
                <button class="btn btn-primary" id="reload-page-btn">Reload Page</button>
            </div>
        `;
        
        // Attach event listener for the button
        setTimeout(() => {
            const reloadBtn = document.getElementById('reload-page-btn');
            if (reloadBtn) {
                reloadBtn.addEventListener('click', () => location.reload());
            }
        }, 0);
    }

    /**
     * Show fatal error (application initialization failure)
     */
    showFatalError(error) {
        const app = document.getElementById('app');
        if (app) {
            app.innerHTML = `
                <div class="error-state fatal-error">
                    <div class="fatal-error-content">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" class="fatal-error-icon">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                        <h3>Application Error</h3>
                        <p>${this.escapeHtml(error.message || 'Failed to initialize application')}</p>
                        <button class="btn btn-primary" id="reload-app-btn">Reload Application</button>
                    </div>
                </div>
            `;
            
            // Attach event listener for the button
            setTimeout(() => {
                const reloadBtn = document.getElementById('reload-app-btn');
                if (reloadBtn) {
                    reloadBtn.addEventListener('click', () => location.reload());
                }
            }, 0);
        }
    }

    /**
     * Update active navigation link
     */
    updateActiveNavLink(path) {
        // Remove active class from all nav links
        document.querySelectorAll('#nav-menu a').forEach(link => {
            link.classList.remove('active');
        });

        // Add active class to matching link
        if (path) {
            const activeLink = document.querySelector(`#nav-menu a[data-route="${path}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
            }
        }
    }

    /**
     * Setup authentication UI (modal and logout button)
     */
    setupAuthUI() {
        const modal = document.getElementById('auth-modal');
        const form = document.getElementById('auth-form');
        const input = document.getElementById('api-key-input');
        const errorDiv = document.getElementById('auth-error');
        const logoutBtn = document.getElementById('logout-btn');

        // Handle form submission
        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const apiKey = input.value.trim();
                
                if (!apiKey) {
                    this.showAuthError('Please enter an API key');
                    return;
                }

                // Store the API key temporarily
                this.apiClient.setAPIKey(apiKey);

                try {
                    // Verify API key by making a test request
                    await this.apiClient.getHealth();
                    
                    // If successful, store the key
                    this.authManager.setAPIKey(apiKey);
                    this.hideAuthModal();
                    
                    // Re-render current route
                    this.router.handleRoute();
                } catch (error) {
                    // Clear the invalid key
                    this.apiClient.clearAPIKey();
                    
                    if (error.status === 401) {
                        this.showAuthError('Invalid API key. Please try again.');
                    } else {
                        this.showAuthError('Unable to verify API key. Please check your connection.');
                    }
                }
            });
        }

        // Handle logout button
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.authManager.clearAPIKey();
                this.showAuthModal();
            });
        }

        // Prevent closing modal by clicking outside if not authenticated
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal && this.authManager.isAuthenticated()) {
                    this.hideAuthModal();
                }
            });
        }
    }

    /**
     * Show authentication modal
     */
    showAuthModal() {
        const modal = document.getElementById('auth-modal');
        const input = document.getElementById('api-key-input');
        const errorDiv = document.getElementById('auth-error');
        
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('active');
            
            // Clear input and error
            if (input) {
                input.value = '';
                setTimeout(() => input.focus(), 100);
            }
            if (errorDiv) {
                errorDiv.textContent = '';
                errorDiv.classList.add('hidden');
            }
        }
    }

    /**
     * Hide authentication modal
     */
    hideAuthModal() {
        const modal = document.getElementById('auth-modal');
        if (modal) {
            modal.classList.remove('active');
            modal.classList.add('hidden');
        }
    }

    /**
     * Show error in auth modal
     */
    showAuthError(message) {
        const errorDiv = document.getElementById('auth-error');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.classList.remove('hidden');
        }
    }

    /**
     * Setup global error handlers
     */
    setupErrorHandlers() {
        // Handle unhandled promise rejections
        window.addEventListener('unhandledrejection', (event) => {
            console.error('Unhandled promise rejection:', event.reason);
            
            // Handle API errors
            if (event.reason instanceof APIError) {
                if (event.reason.status === 401) {
                    this.authManager.clearAPIKey();
                    this.showAuthModal();
                    event.preventDefault();
                }
            }
        });

        // Handle global errors
        window.addEventListener('error', (event) => {
            console.error('Global error:', event.error);
        });

        // Intercept all clicks on links with data-link attribute
        document.addEventListener('click', (e) => {
            if (e.target.matches('a[data-link]')) {
                e.preventDefault();
                const href = e.target.getAttribute('href');
                if (href) {
                    this.router.navigate(href);
                }
            }
        });
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }
}

// Initialize application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        const app = new Application();
        app.init();
    });
} else {
    // DOM already loaded
    const app = new Application();
    app.init();
}
