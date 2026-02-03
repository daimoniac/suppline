/**
 * Security utility module
 * Provides XSS protection and other security-related functions
 */

/**
 * Escape HTML to prevent XSS attacks
 * Uses DOM textContent to safely escape all HTML special characters
 * 
 * @param {string|null|undefined} text - The text to escape
 * @returns {string} The escaped HTML string
 * 
 * @example
 * const userInput = '<script>alert("XSS")</script>';
 * const safe = escapeHtml(userInput);
 * // Result: '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'
 */
export function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
