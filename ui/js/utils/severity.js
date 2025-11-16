/**
 * Severity utilities for vulnerability display
 */

/**
 * Severity levels in order of importance
 */
const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

/**
 * Get color class for severity level
 * @param {string} severity - Severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
 * @returns {string} CSS class name for severity color
 */
function getSeverityColor(severity) {
    if (!severity) return 'severity-unknown';
    
    const level = severity.toUpperCase();
    
    switch (level) {
        case 'CRITICAL':
            return 'severity-critical';
        case 'HIGH':
            return 'severity-high';
        case 'MEDIUM':
            return 'severity-medium';
        case 'LOW':
            return 'severity-low';
        default:
            return 'severity-unknown';
    }
}

/**
 * Get hex color code for severity level
 * @param {string} severity - Severity level
 * @returns {string} Hex color code
 */
function getSeverityHexColor(severity) {
    if (!severity) return '#6c757d';
    
    const level = severity.toUpperCase();
    
    switch (level) {
        case 'CRITICAL':
            return '#dc3545'; // Red
        case 'HIGH':
            return '#fd7e14'; // Orange
        case 'MEDIUM':
            return '#ffc107'; // Yellow
        case 'LOW':
            return '#28a745'; // Green
        default:
            return '#6c757d'; // Gray
    }
}

/**
 * Create severity badge HTML
 * @param {string} severity - Severity level
 * @param {number} count - Optional count to display
 * @returns {string} HTML string for severity badge
 */
function createSeverityBadge(severity, count = null) {
    const colorClass = getSeverityColor(severity);
    const displayText = severity ? severity.toUpperCase() : 'UNKNOWN';
    const countText = count !== null ? ` (${count})` : '';
    
    return `<span class="badge ${colorClass}">${displayText}${countText}</span>`;
}

/**
 * Get severity badge HTML (alias for createSeverityBadge)
 * @param {string} severity - Severity level
 * @param {number} count - Optional count to display
 * @returns {string} HTML string for severity badge
 */
function getSeverityBadge(severity, count = null) {
    return createSeverityBadge(severity, count);
}

/**
 * Create severity icon HTML
 * @param {string} severity - Severity level
 * @returns {string} HTML string for severity icon
 */
function createSeverityIcon(severity) {
    const colorClass = getSeverityColor(severity);
    
    return `<span class="severity-icon ${colorClass}">●</span>`;
}

/**
 * Sort vulnerabilities by severity
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {Array} Sorted array
 */
function sortBySeverity(vulnerabilities) {
    return vulnerabilities.sort((a, b) => {
        const severityA = a.severity ? a.severity.toUpperCase() : 'UNKNOWN';
        const severityB = b.severity ? b.severity.toUpperCase() : 'UNKNOWN';
        
        const indexA = SEVERITY_LEVELS.indexOf(severityA);
        const indexB = SEVERITY_LEVELS.indexOf(severityB);
        
        // If severity not found in list, put at end
        const orderA = indexA === -1 ? SEVERITY_LEVELS.length : indexA;
        const orderB = indexB === -1 ? SEVERITY_LEVELS.length : indexB;
        
        return orderA - orderB;
    });
}

/**
 * Group vulnerabilities by severity
 * Handles both PascalCase (Severity) and camelCase (severity) field names
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @param {string} fieldName - Field name to use (default: 'severity', fallback: 'Severity')
 * @returns {Object} Object with severity levels as keys
 */
function groupBySeverity(vulnerabilities, fieldName = 'severity') {
    const groups = {
        CRITICAL: [],
        HIGH: [],
        MEDIUM: [],
        LOW: [],
        UNKNOWN: [],
    };
    
    vulnerabilities.forEach(vuln => {
        // Try the specified field name first, then fallback to PascalCase
        let severityValue = vuln[fieldName];
        if (!severityValue && fieldName === 'severity') {
            severityValue = vuln.Severity; // Fallback to PascalCase
        }
        
        const severity = severityValue ? severityValue.toUpperCase() : 'UNKNOWN';
        if (groups[severity]) {
            groups[severity].push(vuln);
        } else {
            groups.UNKNOWN.push(vuln);
        }
    });
    
    return groups;
}

/**
 * Get severity counts from vulnerability list
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {Object} Object with counts for each severity level
 */
function getSeverityCounts(vulnerabilities) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
    };
    
    vulnerabilities.forEach(vuln => {
        const severity = vuln.severity ? vuln.severity.toLowerCase() : 'unknown';
        if (counts.hasOwnProperty(severity)) {
            counts[severity]++;
        } else {
            counts.unknown++;
        }
    });
    
    return counts;
}

/**
 * Format vulnerability counts as summary text
 * @param {Object} counts - Severity counts object
 * @returns {string} Formatted summary text
 */
function formatVulnerabilitySummary(counts) {
    const parts = [];
    
    if (counts.critical > 0) {
        parts.push(`${counts.critical} Critical`);
    }
    if (counts.high > 0) {
        parts.push(`${counts.high} High`);
    }
    if (counts.medium > 0) {
        parts.push(`${counts.medium} Medium`);
    }
    if (counts.low > 0) {
        parts.push(`${counts.low} Low`);
    }
    
    if (parts.length === 0) {
        return 'No vulnerabilities';
    }
    
    return parts.join(', ');
}

/**
 * Truncate digest to short format
 * @param {string} digest - Full digest string
 * @param {number} length - Length to truncate to (default 19 for sha256:12chars...)
 * @returns {string} Truncated digest
 */
function truncateDigest(digest) {
    if (!digest) return 'N/A';
    
    // If digest starts with sha256:, keep that prefix plus first 12 chars
    if (digest.startsWith('sha256:')) {
        return digest.substring(0, 19) + '...';
    }
    
    // Otherwise just truncate to 16 chars
    if (digest.length > 16) {
        return digest.substring(0, 16) + '...';
    }
    
    return digest;
}

/**
 * Format package version display
 * @param {string} installedVersion - Currently installed version
 * @param {string} fixedVersion - Version with fix (optional)
 * @returns {string} Formatted version string
 */
function formatVersions(installedVersion, fixedVersion) {
    if (!installedVersion) return 'N/A';
    
    if (fixedVersion) {
        return `${installedVersion} → ${fixedVersion}`;
    }
    
    return installedVersion;
}

// Export for use in other modules
export {
    SEVERITY_LEVELS,
    getSeverityColor,
    getSeverityHexColor,
    createSeverityBadge,
    getSeverityBadge,
    createSeverityIcon,
    sortBySeverity,
    groupBySeverity,
    getSeverityCounts,
    formatVulnerabilitySummary,
    truncateDigest,
    formatVersions,
};
