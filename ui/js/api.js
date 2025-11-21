/**
 * APIClient - Handles all communication with the suppline-ui REST API
 */
class APIClient {
    constructor(baseURL, apiKey = null) {
        this.baseURL = baseURL || '';
        this.apiKey = apiKey;
        this.maxRetries = 3;
        this.retryDelay = 1000; // ms
    }

    /**
     * Set the API key for authentication
     */
    setAPIKey(apiKey) {
        this.apiKey = apiKey;
    }

    /**
     * Clear the stored API key
     */
    clearAPIKey() {
        this.apiKey = null;
    }

    /**
     * Get headers for API requests
     */
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };

        if (this.apiKey) {
            headers['Authorization'] = `Bearer ${this.apiKey}`;
        }

        return headers;
    }

    /**
     * Make an API request with retry logic
     */
    async request(endpoint, options = {}, retryCount = 0) {
        const url = `${this.baseURL}${endpoint}`;
        
        try {
            const response = await fetch(url, {
                method: 'GET',
                mode: 'cors',
                credentials: 'omit',
                ...options,
                headers: {
                    ...this.getHeaders(),
                    ...options.headers,
                },
            });

            // Handle authentication errors
            if (response.status === 401) {
                throw new APIError('Unauthorized', 401, 'Authentication required');
            }

            // Handle other HTTP errors
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new APIError(
                    errorData.error || 'Request failed',
                    response.status,
                    errorData.details || response.statusText
                );
            }

            return await response.json();
        } catch (error) {
            // Retry on network errors
            if (error.name === 'TypeError' && retryCount < this.maxRetries) {
                await this.sleep(this.retryDelay * (retryCount + 1));
                return this.request(endpoint, options, retryCount + 1);
            }

            throw error;
        }
    }

    /**
     * Sleep utility for retry delays
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // ==================== Scans API ====================

    /**
     * Get scans with optional filters
     * @param {Object} filters - Filter parameters
     * @param {string} filters.repository - Filter by repository name
     * @param {boolean} filters.policy_passed - Filter by policy status
     * @param {number} filters.limit - Limit number of results
     * @param {number} filters.offset - Offset for pagination
     */
    async getScans(filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.repository) params.append('repository', filters.repository);
        if (filters.policy_passed !== undefined) params.append('policy_passed', filters.policy_passed);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);

        const queryString = params.toString();
        const endpoint = `/api/v1/scans${queryString ? '?' + queryString : ''}`;
        
        return this.request(endpoint);
    }

    /**
     * Get a specific scan by digest
     * @param {string} digest - Image digest
     */
    async getScanByDigest(digest) {
        return this.request(`/api/v1/scans/${encodeURIComponent(digest)}`);
    }

    /**
     * Get failed images (policy_passed=false)
     * @param {number} limit - Limit number of results
     */
    async getFailedImages(limit = 50) {
        return this.getScans({ policy_passed: false, limit });
    }

    /**
     * Trigger a scan for an image or repository
     * @param {Object} params - Scan parameters
     * @param {string} params.digest - Image digest (optional)
     * @param {string} params.repository - Repository name (optional)
     */
    async triggerScan(params = {}) {
        return this.request('/api/v1/scans/trigger', {
            method: 'POST',
            body: JSON.stringify(params),
        });
    }

    // ==================== Vulnerabilities API ====================

    /**
     * Query vulnerabilities with filters
     * @param {Object} filters - Filter parameters
     * @param {string} filters.cve_id - Filter by CVE ID
     * @param {string} filters.severity - Filter by severity
     * @param {string} filters.package_name - Filter by package name
     * @param {string} filters.repository - Filter by repository
     * @param {number} filters.limit - Limit number of results
     * @param {number} filters.offset - Offset for pagination
     */
    async queryVulnerabilities(filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.cve_id) params.append('cve_id', filters.cve_id);
        if (filters.severity) params.append('severity', filters.severity);
        if (filters.package_name) params.append('package_name', filters.package_name);
        if (filters.repository) params.append('repository', filters.repository);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);

        const queryString = params.toString();
        const endpoint = `/api/v1/vulnerabilities${queryString ? '?' + queryString : ''}`;
        
        return this.request(endpoint);
    }

    // ==================== Tolerations API ====================

    /**
     * Get tolerations with optional filters
     * @param {Object} filters - Filter parameters
     * @param {string} filters.cve_id - Filter by CVE ID
     * @param {string} filters.repository - Filter by repository
     * @param {boolean} filters.expired - Filter by expiration status
     * @param {boolean} filters.expiring_soon - Filter tolerations expiring within 7 days
     * @param {number} filters.limit - Limit number of results
     * @param {number} filters.offset - Offset for pagination
     */
    async getTolerations(filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.cve_id) params.append('cve_id', filters.cve_id);
        if (filters.repository) params.append('repository', filters.repository);
        if (filters.expired !== undefined) params.append('expired', filters.expired);
        if (filters.expiring_soon !== undefined) params.append('expiring_soon', filters.expiring_soon);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);

        const queryString = params.toString();
        const endpoint = `/api/v1/tolerations${queryString ? '?' + queryString : ''}`;
        
        return this.request(endpoint);
    }

    // ==================== Policy API ====================

    /**
     * Re-evaluate policy for a repository
     * @param {string} repository - Repository name
     */
    async reevaluatePolicy(repository) {
        return this.request('/api/v1/policy/reevaluate', {
            method: 'POST',
            body: JSON.stringify({ repository }),
        });
    }

    // ==================== Integration API ====================

    /**
     * Get the cosign public key
     */
    async getPublicKey() {
        const url = `${this.baseURL}/api/v1/integration/publickey`;
        
        try {
            const response = await fetch(url, {
                method: 'GET',
                mode: 'cors',
                credentials: 'omit',
                headers: this.getHeaders(),
            });

            if (!response.ok) {
                throw new APIError('Failed to fetch public key', response.status, response.statusText);
            }

            return await response.text();
        } catch (error) {
            throw error;
        }
    }

    /**
     * Get the Kyverno ClusterPolicy YAML
     */
    async getKyvernoPolicy() {
        const url = `${this.baseURL}/api/v1/integration/kyverno/policy`;
        
        try {
            const response = await fetch(url, {
                method: 'GET',
                mode: 'cors',
                credentials: 'omit',
                headers: this.getHeaders(),
            });

            if (!response.ok) {
                throw new APIError('Failed to fetch Kyverno policy', response.status, response.statusText);
            }

            return await response.text();
        } catch (error) {
            throw error;
        }
    }

    // ==================== Repositories API ====================

    /**
     * Get repositories with optional filters
     * @param {Object} filters - Filter parameters
     * @param {string} filters.search - Filter by repository name
     * @param {number} filters.limit - Limit number of results
     * @param {number} filters.offset - Offset for pagination
     */
    async getRepositories(filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.search) params.append('search', filters.search);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);

        const queryString = params.toString();
        const endpoint = `/api/v1/repositories${queryString ? '?' + queryString : ''}`;
        
        return this.request(endpoint);
    }

    /**
     * Get repository details with tags
     * @param {string} name - Repository name
     * @param {Object} filters - Filter parameters
     * @param {string} filters.search - Filter by tag name
     * @param {number} filters.limit - Limit number of results
     * @param {number} filters.offset - Offset for pagination
     */
    async getRepository(name, filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.search) params.append('search', filters.search);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);

        const queryString = params.toString();
        const endpoint = `/api/v1/repositories/${encodeURIComponent(name)}${queryString ? '?' + queryString : ''}`;
        
        return this.request(endpoint);
    }

    /**
     * Trigger rescan for entire repository
     * @param {string} name - Repository name
     */
    async triggerRepositoryRescan(name) {
        return this.request(`/api/v1/repositories/${encodeURIComponent(name)}/rescan`, {
            method: 'POST',
            body: JSON.stringify({}),
        });
    }

    /**
     * Trigger rescan for specific tag
     * @param {string} name - Repository name
     * @param {string} tag - Tag name
     */
    async triggerTagRescan(name, tag) {
        return this.request(`/api/v1/repositories/${encodeURIComponent(name)}/tags/${encodeURIComponent(tag)}/rescan`, {
            method: 'POST',
            body: JSON.stringify({}),
        });
    }

    // ==================== Health API ====================

    /**
     * Get health status
     */
    async getHealth() {
        return this.request('/health');
    }
}

/**
 * Custom error class for API errors
 */
class APIError extends Error {
    constructor(message, status, details) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.details = details;
    }
}

// Export for use in other modules
export { APIClient, APIError };
