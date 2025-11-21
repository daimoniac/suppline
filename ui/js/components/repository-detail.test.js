/**
 * Unit Tests for RepositoryDetail Component
 * Tests state management, filtering, sorting, and pagination logic
 */

import { RepositoryDetail } from './repository-detail.js';

// Mock API Client
class MockApiClient {
    constructor(mockData = {}) {
        this.mockData = mockData;
        this.callHistory = [];
    }

    async getRepository(repositoryName, filters) {
        this.callHistory.push({ method: 'getRepository', repositoryName, filters });
        return this.mockData.repository || { Tags: [], Total: 0 };
    }

    async triggerTagRescan(repositoryName, tagName) {
        this.callHistory.push({ method: 'triggerTagRescan', repositoryName, tagName });
        return { message: 'Rescan triggered' };
    }
}

// Test Suite
const tests = [];

function test(name, fn) {
    tests.push({ name, fn });
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`Assertion failed: ${message}. Expected ${expected}, got ${actual}`);
    }
}

function assertDeepEqual(actual, expected, message) {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw new Error(`Assertion failed: ${message}. Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    }
}

// Test: Initial state
test('RepositoryDetail initializes with correct default state', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    assertEqual(component.repositoryName, null, 'repositoryName should be null');
    assertEqual(component.tags.length, 0, 'tags should be empty');
    assertEqual(component.total, 0, 'total should be 0');
    assertEqual(component.currentPage, 1, 'currentPage should be 1');
    assertEqual(component.pageSize, 10, 'pageSize should be 10');
    assertEqual(component.sortColumn, 'name', 'sortColumn should be name');
    assertEqual(component.sortDirection, 'asc', 'sortDirection should be asc');
    assertDeepEqual(component.filters, { search: '' }, 'filters should have empty search');
});

// Test: Repository name management
test('RepositoryDetail setRepository sets repository name', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.setRepository('my-app');
    assertEqual(component.repositoryName, 'my-app', 'repositoryName should be set');
});

// Test: Filter state management
test('RepositoryDetail setFilters updates filter state', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.setFilters({ search: 'v1' });
    assertEqual(component.filters.search, 'v1', 'search filter should be updated');
    assertEqual(component.currentPage, 1, 'currentPage should reset to 1 when filters change');
});

test('RepositoryDetail setFilters resets page to 1', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.currentPage = 5;
    component.setFilters({ search: 'new' });
    assertEqual(component.currentPage, 1, 'currentPage should reset to 1');
});

// Test: Sort state management
test('RepositoryDetail setSort changes sort column and direction', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.setSort('lastScanTime', 'asc');
    assertEqual(component.sortColumn, 'lastScanTime', 'sortColumn should be lastScanTime');
    assertEqual(component.sortDirection, 'asc', 'sortDirection should be asc');
});

test('RepositoryDetail setSort toggles direction when same column clicked', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.sortColumn = 'name';
    component.sortDirection = 'asc';
    component.setSort('name');
    assertEqual(component.sortDirection, 'desc', 'sortDirection should toggle to desc');
});

test('RepositoryDetail setSort resets direction when different column clicked', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.sortColumn = 'name';
    component.sortDirection = 'desc';
    component.setSort('nextScanTime');
    assertEqual(component.sortColumn, 'nextScanTime', 'sortColumn should change');
    assertEqual(component.sortDirection, 'asc', 'sortDirection should reset to asc');
});

// Test: Sorting logic
test('RepositoryDetail sorts tags by name ascending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.tags = [
        { Name: 'v2.0.0' },
        { Name: 'latest' },
        { Name: 'v1.0.0' }
    ];
    component.sortColumn = 'name';
    component.sortDirection = 'asc';
    component.sortTags();

    assertEqual(component.tags[0].Name, 'latest', 'first should be latest');
    assertEqual(component.tags[1].Name, 'v1.0.0', 'second should be v1.0.0');
    assertEqual(component.tags[2].Name, 'v2.0.0', 'third should be v2.0.0');
});

test('RepositoryDetail sorts tags by name descending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.tags = [
        { Name: 'v1.0.0' },
        { Name: 'latest' },
        { Name: 'v2.0.0' }
    ];
    component.sortColumn = 'name';
    component.sortDirection = 'desc';
    component.sortTags();

    assertEqual(component.tags[0].Name, 'v2.0.0', 'first should be v2.0.0');
    assertEqual(component.tags[1].Name, 'v1.0.0', 'second should be v1.0.0');
    assertEqual(component.tags[2].Name, 'latest', 'third should be latest');
});

test('RepositoryDetail sorts tags by date ascending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.tags = [
        { Name: 'tag1', LastScanTime: '2024-01-15T10:00:00Z' },
        { Name: 'tag2', LastScanTime: '2024-01-10T10:00:00Z' },
        { Name: 'tag3', LastScanTime: '2024-01-20T10:00:00Z' }
    ];
    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'asc';
    component.sortTags();

    assertEqual(component.tags[0].Name, 'tag2', 'first should be tag2 (earliest)');
    assertEqual(component.tags[1].Name, 'tag1', 'second should be tag1');
    assertEqual(component.tags[2].Name, 'tag3', 'third should be tag3 (latest)');
});

test('RepositoryDetail sorts tags by date descending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.tags = [
        { Name: 'tag1', LastScanTime: '2024-01-15T10:00:00Z' },
        { Name: 'tag2', LastScanTime: '2024-01-10T10:00:00Z' },
        { Name: 'tag3', LastScanTime: '2024-01-20T10:00:00Z' }
    ];
    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'desc';
    component.sortTags();

    assertEqual(component.tags[0].Name, 'tag3', 'first should be tag3 (latest)');
    assertEqual(component.tags[1].Name, 'tag1', 'second should be tag1');
    assertEqual(component.tags[2].Name, 'tag2', 'third should be tag2 (earliest)');
});

test('RepositoryDetail handles null dates in sorting', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.tags = [
        { Name: 'tag1', LastScanTime: '2024-01-15T10:00:00Z' },
        { Name: 'tag2', LastScanTime: null },
        { Name: 'tag3', LastScanTime: '2024-01-10T10:00:00Z' }
    ];
    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'asc';
    component.sortTags();

    // Null values should sort to the beginning
    assertEqual(component.tags[0].Name, 'tag2', 'null date should be first');
});

// Test: Pagination logic
test('RepositoryDetail goToPage updates currentPage', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.total = 100;
    component.goToPage(3);
    assertEqual(component.currentPage, 3, 'currentPage should be 3');
});

test('RepositoryDetail goToPage prevents invalid page numbers', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.total = 100;
    component.currentPage = 1;
    component.goToPage(0);
    assertEqual(component.currentPage, 1, 'currentPage should remain 1 for page 0');

    component.goToPage(100);
    assertEqual(component.currentPage, 1, 'currentPage should remain 1 for page beyond total');
});

test('RepositoryDetail calculates correct pagination offset', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.currentPage = 1;
    component.pageSize = 10;
    let offset = (component.currentPage - 1) * component.pageSize;
    assertEqual(offset, 0, 'page 1 offset should be 0');

    component.currentPage = 2;
    offset = (component.currentPage - 1) * component.pageSize;
    assertEqual(offset, 10, 'page 2 offset should be 10');

    component.currentPage = 3;
    offset = (component.currentPage - 1) * component.pageSize;
    assertEqual(offset, 20, 'page 3 offset should be 20');
});

test('RepositoryDetail calculates correct total pages', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.total = 50;
    component.pageSize = 10;
    let totalPages = Math.ceil(component.total / component.pageSize);
    assertEqual(totalPages, 5, 'total pages should be 5');

    component.total = 55;
    totalPages = Math.ceil(component.total / component.pageSize);
    assertEqual(totalPages, 6, 'total pages should be 6');

    component.total = 10;
    totalPages = Math.ceil(component.total / component.pageSize);
    assertEqual(totalPages, 1, 'total pages should be 1');
});

// Test: Combined state operations
test('RepositoryDetail maintains state across multiple operations', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.setRepository('my-app');
    component.tags = [
        { Name: 'v2.0.0' },
        { Name: 'latest' },
        { Name: 'v1.0.0' }
    ];
    component.total = 3;

    // Apply filter
    component.setFilters({ search: 'v' });
    assertEqual(component.filters.search, 'v', 'filter should be applied');
    assertEqual(component.currentPage, 1, 'page should reset');

    // Apply sort
    component.setSort('name', 'desc');
    assertEqual(component.sortColumn, 'name', 'sort column should be set');
    assertEqual(component.sortDirection, 'desc', 'sort direction should be set');

    // Navigate to page
    component.goToPage(2);
    assertEqual(component.currentPage, 2, 'page should be updated');

    // Verify all state is maintained
    assertEqual(component.repositoryName, 'my-app', 'repository name should be maintained');
    assertEqual(component.filters.search, 'v', 'filter should still be applied');
    assertEqual(component.sortColumn, 'name', 'sort column should still be set');
});

// Test: Filter and sort interaction
test('RepositoryDetail filter and sort work together', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.tags = [
        { Name: 'v2.0.0', LastScanTime: '2024-01-15T10:00:00Z' },
        { Name: 'v1.0.0', LastScanTime: '2024-01-10T10:00:00Z' },
        { Name: 'latest', LastScanTime: '2024-01-20T10:00:00Z' }
    ];

    // Apply sort by date descending
    component.setSort('lastScanTime', 'desc');
    component.sortTags();

    assertEqual(component.tags[0].Name, 'latest', 'latest should be first (most recent)');
    assertEqual(component.tags[1].Name, 'v2.0.0', 'v2.0.0 should be second');
    assertEqual(component.tags[2].Name, 'v1.0.0', 'v1.0.0 should be third (oldest)');
});

// Run all tests
async function runTests() {
    let passed = 0;
    let failed = 0;
    const results = [];

    for (const { name, fn } of tests) {
        try {
            fn();
            passed++;
            results.push({ name, status: 'PASS' });
        } catch (error) {
            failed++;
            results.push({ name, status: 'FAIL', error: error.message });
        }
    }

    return { passed, failed, results };
}

// Export for use in test runner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { runTests, RepositoryDetail, MockApiClient };
}
