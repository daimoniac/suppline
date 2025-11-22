/**
 * Date formatting utilities
 * Handles Unix timestamps (int64 seconds) from the API
 */

/**
 * Convert Unix timestamp to Date object
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @returns {Date|null} Date object or null if invalid
 */
function parseTimestamp(timestamp) {
    if (!timestamp) return null;
    
    try {
        let date;
        
        // Handle Unix timestamp (number in seconds)
        if (typeof timestamp === 'number') {
            date = new Date(timestamp * 1000); // Convert seconds to milliseconds
        } 
        // Handle ISO date string (for backwards compatibility)
        else if (typeof timestamp === 'string') {
            date = new Date(timestamp);
        } 
        else {
            return null;
        }
        
        if (isNaN(date.getTime())) {
            return null;
        }
        
        return date;
    } catch (error) {
        console.error('Error parsing timestamp:', error);
        return null;
    }
}

/**
 * Format a timestamp to a human-readable format
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @param {boolean} includeTime - Whether to include time in output
 * @returns {string} Formatted date string
 */
function formatDate(timestamp, includeTime = true) {
    if (!timestamp) return 'N/A';
    
    try {
        const date = parseTimestamp(timestamp);
        
        if (!date) {
            return 'Invalid Date';
        }
        
        const options = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        };
        
        if (includeTime) {
            options.hour = '2-digit';
            options.minute = '2-digit';
        }
        
        return date.toLocaleString('en-US', options);
    } catch (error) {
        console.error('Error formatting date:', error);
        return 'Invalid Date';
    }
}

/**
 * Format a timestamp to relative time (e.g., "2 hours ago", "3 days ago")
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @returns {string} Relative time string
 */
function formatRelativeTime(timestamp) {
    if (!timestamp) return 'N/A';
    
    try {
        const date = parseTimestamp(timestamp);
        
        if (!date) return 'N/A';
        
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);
        
        if (diffSec < 60) {
            return 'just now';
        } else if (diffMin < 60) {
            return `${diffMin} minute${diffMin !== 1 ? 's' : ''} ago`;
        } else if (diffHour < 24) {
            return `${diffHour} hour${diffHour !== 1 ? 's' : ''} ago`;
        } else if (diffDay < 7) {
            return `${diffDay} day${diffDay !== 1 ? 's' : ''} ago`;
        } else if (diffDay < 30) {
            const weeks = Math.floor(diffDay / 7);
            return `${weeks} week${weeks !== 1 ? 's' : ''} ago`;
        } else if (diffDay < 365) {
            const months = Math.floor(diffDay / 30);
            return `${months} month${months !== 1 ? 's' : ''} ago`;
        } else {
            const years = Math.floor(diffDay / 365);
            return `${years} year${years !== 1 ? 's' : ''} ago`;
        }
    } catch (error) {
        console.error('Error formatting relative time:', error);
        return 'N/A';
    }
}

/**
 * Calculate days until a future date
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @returns {number|null} Number of days until date (negative if past), null if invalid
 */
function daysUntil(timestamp) {
    if (!timestamp) return null;
    
    try {
        const date = parseTimestamp(timestamp);
        
        if (!date) return null;
        
        const now = new Date();
        
        // Reset time to midnight for accurate day calculation
        date.setHours(0, 0, 0, 0);
        now.setHours(0, 0, 0, 0);
        
        const diffMs = date - now;
        const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
        
        return diffDays;
    } catch (error) {
        console.error('Error calculating days until:', error);
        return null;
    }
}

/**
 * Check if a timestamp is in the past
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @returns {boolean} True if date is in the past
 */
function isPast(timestamp) {
    if (!timestamp) return false;
    
    try {
        const date = parseTimestamp(timestamp);
        
        if (!date) return false;
        
        const now = new Date();
        return date < now;
    } catch (error) {
        return false;
    }
}

/**
 * Check if a timestamp is within the next N days
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @param {number} days - Number of days to check
 * @returns {boolean} True if date is within the next N days
 */
function isWithinDays(timestamp, days) {
    const daysRemaining = daysUntil(timestamp);
    return daysRemaining !== null && daysRemaining >= 0 && daysRemaining <= days;
}

/**
 * Format expiration status with days remaining
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @returns {string} Formatted expiration status
 */
function formatExpirationStatus(timestamp) {
    if (!timestamp) return 'No expiration';
    
    const days = daysUntil(timestamp);
    
    if (days === null) return 'Invalid date';
    if (days < 0) return 'Expired';
    if (days === 0) return 'Expires today';
    if (days === 1) return 'Expires tomorrow';
    if (days <= 7) return `Expires in ${days} days`;
    if (days <= 30) return `Expires in ${Math.ceil(days / 7)} weeks`;
    
    return formatDate(timestamp, false);
}

/**
 * Get expiration status class for styling
 * @param {number|string} timestamp - Unix timestamp in seconds or ISO date string
 * @returns {string} CSS class name
 */
function getExpirationStatusClass(timestamp) {
    if (!timestamp) return 'no-expiration';
    
    const days = daysUntil(timestamp);
    
    if (days === null) return 'invalid';
    if (days < 0) return 'expired';
    if (days <= 7) return 'expiring-soon';
    
    return 'active';
}

// Export for use in other modules
export {
    parseTimestamp,
    formatDate,
    formatRelativeTime,
    daysUntil,
    isPast,
    isWithinDays,
    formatExpirationStatus,
    getExpirationStatusClass,
};
