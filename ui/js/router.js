/**
 * Router - Client-side routing using History API
 */
class Router {
    constructor() {
        this.routes = new Map();
        this.currentRoute = null;
        this.notFoundHandler = null;
        
        // Listen for browser navigation events
        window.addEventListener('popstate', () => this.handleRoute());
        
        // Intercept link clicks for client-side navigation
        document.addEventListener('click', (e) => {
            if (e.target.matches('a[data-link]')) {
                e.preventDefault();
                this.navigate(e.target.getAttribute('href'));
            }
        });
    }

    /**
     * Register a route with its handler
     * @param {string} path - Route path (can include :param for dynamic segments)
     * @param {Function} handler - Function to call when route matches
     */
    addRoute(path, handler) {
        this.routes.set(path, {
            pattern: this.pathToRegex(path),
            handler,
            path,
        });
    }

    /**
     * Set handler for 404 not found
     * @param {Function} handler - Function to call when no route matches
     */
    setNotFoundHandler(handler) {
        this.notFoundHandler = handler;
    }

    /**
     * Convert path pattern to regex for matching
     * @param {string} path - Route path with optional :param segments
     */
    pathToRegex(path) {
        // Escape special regex characters except : and /
        const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        
        // Convert :param to named capture groups
        const pattern = escaped.replace(/:(\w+)/g, '(?<$1>[^/]+)');
        
        return new RegExp(`^${pattern}$`);
    }

    /**
     * Match current URL against registered routes
     */
    matchRoute() {
        const path = window.location.pathname;
        
        for (const [, route] of this.routes) {
            const match = path.match(route.pattern);
            if (match) {
                return {
                    route,
                    params: match.groups || {},
                };
            }
        }
        
        return null;
    }

    /**
     * Get query parameters from URL
     */
    getQueryParams() {
        const params = {};
        const searchParams = new URLSearchParams(window.location.search);
        
        for (const [key, value] of searchParams) {
            params[key] = value;
        }
        
        return params;
    }

    /**
     * Navigate to a new route
     * @param {string} path - Path to navigate to
     * @param {Object} queryParams - Optional query parameters
     * @param {boolean} replace - Replace current history entry instead of pushing
     */
    navigate(path, queryParams = null, replace = false) {
        let url = path;
        
        // Add query parameters if provided
        if (queryParams) {
            const params = new URLSearchParams(queryParams);
            url += `?${params.toString()}`;
        }
        
        // Update browser history
        if (replace) {
            window.history.replaceState(null, '', url);
        } else {
            window.history.pushState(null, '', url);
        }
        
        // Handle the new route
        this.handleRoute();
    }

    /**
     * Handle the current route
     */
    async handleRoute() {
        const match = this.matchRoute();
        
        if (match) {
            this.currentRoute = match.route.path;
            const queryParams = this.getQueryParams();
            
            try {
                await match.route.handler(match.params, queryParams);
            } catch (error) {
                console.error('Route handler error:', error);
                if (this.notFoundHandler) {
                    this.notFoundHandler(error);
                }
            }
        } else {
            this.currentRoute = null;
            if (this.notFoundHandler) {
                this.notFoundHandler();
            }
        }
    }

    /**
     * Get current route path
     */
    getCurrentRoute() {
        return this.currentRoute;
    }

    /**
     * Build URL with query parameters
     * @param {string} path - Base path
     * @param {Object} queryParams - Query parameters
     */
    buildURL(path, queryParams = {}) {
        const params = new URLSearchParams(queryParams);
        const queryString = params.toString();
        return queryString ? `${path}?${queryString}` : path;
    }

    /**
     * Preserve current query parameters when navigating
     * @param {string} path - Path to navigate to
     * @param {Object} additionalParams - Additional query parameters to add/override
     */
    navigatePreservingQuery(path, additionalParams = {}) {
        const currentParams = this.getQueryParams();
        const mergedParams = { ...currentParams, ...additionalParams };
        this.navigate(path, mergedParams);
    }

    /**
     * Initialize router and handle initial route
     */
    init() {
        this.handleRoute();
    }
}

// Export for use in other modules
export { Router };
