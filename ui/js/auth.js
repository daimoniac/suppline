/**
 * AuthManager - Handles API key authentication and storage
 */
class AuthManager {
    constructor(apiClient) {
        this.apiClient = apiClient;
        this.storageKey = 'stk_api_key';
        this.modalId = 'auth-modal';
        this.onAuthChangeCallbacks = [];
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return this.getAPIKey() !== null;
    }

    /**
     * Get stored API key from localStorage
     */
    getAPIKey() {
        return localStorage.getItem(this.storageKey);
    }

    /**
     * Store API key in localStorage
     * @param {string} apiKey - API key to store
     */
    setAPIKey(apiKey) {
        localStorage.setItem(this.storageKey, apiKey);
        this.apiClient.setAPIKey(apiKey);
        this.notifyAuthChange(true);
    }

    /**
     * Clear stored API key
     */
    clearAPIKey() {
        localStorage.removeItem(this.storageKey);
        this.apiClient.clearAPIKey();
        this.notifyAuthChange(false);
    }

    /**
     * Initialize authentication on app load
     */
    init() {
        const apiKey = this.getAPIKey();
        if (apiKey) {
            this.apiClient.setAPIKey(apiKey);
        }
    }

    /**
     * Show authentication modal
     */
    showAuthModal() {
        const modal = document.getElementById(this.modalId);
        if (modal) {
            modal.classList.add('active');
            
            // Focus on input field and pre-fill if available
            const input = modal.querySelector('#api-key-input');
            if (input) {
                const storedKey = this.getAPIKey();
                input.value = storedKey || '';
                input.focus();
            }
            
            // Clear any previous error messages
            const errorEl = modal.querySelector('#auth-error');
            if (errorEl) {
                errorEl.textContent = '';
                errorEl.classList.add('hidden');
            }
        }
    }

    /**
     * Hide authentication modal
     */
    hideAuthModal() {
        const modal = document.getElementById(this.modalId);
        if (modal) {
            modal.classList.remove('active');
        }
    }

    /**
     * Handle authentication form submission
     * @param {string} apiKey - API key entered by user
     */
    async authenticate(apiKey) {
        if (!apiKey || apiKey.trim() === '') {
            this.showAuthError('Please enter an API key');
            return false;
        }

        // Store the API key temporarily
        this.apiClient.setAPIKey(apiKey);

        try {
            // Verify API key by making a test request
            await this.apiClient.getHealth();
            
            // If successful, store the key
            this.setAPIKey(apiKey);
            this.hideAuthModal();
            return true;
        } catch (error) {
            // Clear the invalid key
            this.apiClient.clearAPIKey();
            
            if (error.status === 401) {
                this.showAuthError('Invalid API key. Please try again.');
            } else {
                this.showAuthError('Unable to verify API key. Please check your connection.');
            }
            return false;
        }
    }

    /**
     * Show error message in auth modal
     * @param {string} message - Error message to display
     */
    showAuthError(message) {
        const modal = document.getElementById(this.modalId);
        if (modal) {
            const errorEl = modal.querySelector('#auth-error');
            if (errorEl) {
                errorEl.textContent = message;
                errorEl.classList.remove('hidden');
            }
        }
    }

    /**
     * Handle logout
     */
    logout() {
        this.clearAPIKey();
        this.showAuthModal();
    }

    /**
     * Handle 401 Unauthorized response
     */
    handle401() {
        this.clearAPIKey();
        this.showAuthModal();
    }

    /**
     * Register callback for authentication state changes
     * @param {Function} callback - Function to call when auth state changes
     */
    onAuthChange(callback) {
        this.onAuthChangeCallbacks.push(callback);
    }

    /**
     * Notify all registered callbacks of auth state change
     * @param {boolean} isAuthenticated - Current authentication state
     */
    notifyAuthChange(isAuthenticated) {
        this.onAuthChangeCallbacks.forEach(callback => {
            try {
                callback(isAuthenticated);
            } catch (error) {
                console.error('Auth change callback error:', error);
            }
        });
    }

    /**
     * Setup authentication modal UI and event listeners
     */
    setupAuthModal() {
        // Create modal HTML if it doesn't exist
        if (!document.getElementById(this.modalId)) {
            this.createAuthModal();
        }

        const modal = document.getElementById(this.modalId);
        const form = modal.querySelector('#auth-form');
        const input = modal.querySelector('#api-key-input');
        const cancelBtn = modal.querySelector('.auth-cancel');

        // Handle form submission
        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const apiKey = input.value.trim();
                await this.authenticate(apiKey);
            });
        }

        // Handle cancel button
        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => {
                // Only allow cancel if already authenticated
                if (this.isAuthenticated()) {
                    this.hideAuthModal();
                }
            });
        }

        // Prevent closing modal by clicking outside if not authenticated
        modal.addEventListener('click', (e) => {
            if (e.target === modal && this.isAuthenticated()) {
                this.hideAuthModal();
            }
        });

        // Handle Enter key in input
        if (input) {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    form.dispatchEvent(new Event('submit'));
                }
            });
        }
    }

    /**
     * Create authentication modal HTML
     */
    createAuthModal() {
        const modalHTML = `
            <div id="${this.modalId}" class="modal">
                <div class="modal-content auth-modal-content">
                    <h2>Authentication Required</h2>
                    <p>Please enter your API key to access the dashboard.</p>
                    <form id="auth-form">
                        <div class="form-group" style="display: none;">
                            <label for="api-username">Username:</label>
                            <input 
                                type="text" 
                                id="api-username" 
                                name="username"
                                class="form-control" 
                                value="suppline-api"
                                autocomplete="username"
                                readonly
                            />
                        </div>
                        <div class="form-group">
                            <label for="api-key-input">API Key:</label>
                            <input 
                                type="password" 
                                id="api-key-input" 
                                class="form-control" 
                                placeholder="Enter your API key"
                                autocomplete="current-password"
                                required
                            />
                        </div>
                        <div class="auth-error hidden"></div>
                        <div class="modal-actions">
                            <button type="submit" class="btn btn-primary">Authenticate</button>
                            <button type="button" class="btn btn-secondary auth-cancel">Cancel</button>
                        </div>
                    </form>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }

    /**
     * Setup logout button event listener
     */
    setupLogoutButton() {
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.logout();
            });
        }
    }
}

// Export for use in other modules
export { AuthManager };
