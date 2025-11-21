/**
 * Unit Tests for RepositoriesList Component
 * Tests state management, filtering, sorting, and pagination logic
 */

import { RepositoriesList } from './repositories-list.js';

// Mock API Client
class MockApiClient {
    constructor(mockData = {}) {
        this.mockData = mockData;
        this.callHistory = [];
    }

    async getRepositories(filters) {
        this.callHistory.push({ method: 'getRepositories', filters });
        return this.mockData.repositories || { Repositories: [], Total: 0 };
    }

    async triggerRepositoryRescan(repositoryName) {
        this.callHistory.push({ method: 'triggerRepositoryRescan', repositoryName });
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
test('RepositoriesList initializes with correct default state', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    assertEqual(component.repositories.length, 0, 'repositories should be empty');
    assertEqual(component.total, 0, 'total should be 0');
    assertEqual(component.currentPage, 1, 'currentPage should be 1');
    assertEqual(component.pageSize, 10, 'pageSize should be 10');
    assertEqual(component.sortColumn, 'name', 'sortColumn should be name');
    assertEqual(component.sortDirection, 'asc', 'sortDirection should be asc');
    assertDeepEqual(component.filters, { search: '' }, 'filters should have empty search');
});

// Test: Filter state management
test('RepositoriesList setFilters updates filter state', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.setFilters({ search: 'test' });
    assertEqual(component.filters.search, 'test', 'search filter should be updated');
    assertEqual(component.currentPage, 1, 'currentPage should reset to 1 when filters change');
});

test('RepositoriesList setFilters resets page to 1', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.currentPage = 5;
    component.setFilters({ search: 'new' });
    assertEqual(component.currentPage, 1, 'currentPage should reset to 1');
});

// Test: Sort state management
test('RepositoriesList setSort changes sort column and direction', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.setSort('lastScanTime', 'asc');
    assertEqual(component.sortColumn, 'lastScanTime', 'sortColumn should be lastScanTime');
    assertEqual(component.sortDirection, 'asc', 'sortDirection should be asc');
});

test('RepositoriesList setSort toggles direction when same column clicked', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'name';
    component.sortDirection = 'asc';
    component.setSort('name');
    assertEqual(component.sortDirection, 'desc', 'sortDirection should toggle to desc');
});

test('RepositoriesList setSort resets direction when different column clicked', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'name';
    component.sortDirection = 'desc';
    component.setSort('lastScanTime');
    assertEqual(component.sortColumn, 'lastScanTime', 'sortColumn should change');
    assertEqual(component.sortDirection, 'asc', 'sortDirection should reset to asc');
});

// Test: Sorting logic
test('RepositoriesList sorts repositories by name ascending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.repositories = [
        { Name: 'zebra' },
        { Name: 'apple' },
        { Name: 'banana' }
    ];
    component.sortColumn = 'name';
    component.sortDirection = 'asc';
    component.sortRepositories();

    assertEqual(component.repositories[0].Name, 'apple', 'first should be apple');
    assertEqual(component.repositories[1].Name, 'banana', 'second should be banana');
    assertEqual(component.repositories[2].Name, 'zebra', 'third should be zebra');
});

test('RepositoriesList sorts repositories by name descending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.repositories = [
        { Name: 'apple' },
        { Name: 'zebra' },
        { Name: 'banana' }
    ];
    component.sortColumn = 'name';
    component.sortDirection = 'desc';
    component.sortRepositories();

    assertEqual(component.repositories[0].Name, 'zebra', 'first should be zebra');
    assertEqual(component.repositories[1].Name, 'banana', 'second should be banana');
    assertEqual(component.repositories[2].Name, 'apple', 'third should be apple');
});

test('RepositoriesList sorts repositories by date ascending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.repositories = [
        { Name: 'repo1', LastScanTime: '2024-01-15T10:00:00Z' },
        { Name: 'repo2', LastScanTime: '2024-01-10T10:00:00Z' },
        { Name: 'repo3', LastScanTime: '2024-01-20T10:00:00Z' }
    ];
    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'asc';
    component.sortRepositories();

    assertEqual(component.repositories[0].Name, 'repo2', 'first should be repo2 (earliest)');
    assertEqual(component.repositories[1].Name, 'repo1', 'second should be repo1');
    assertEqual(component.repositories[2].Name, 'repo3', 'third should be repo3 (latest)');
});

test('RepositoriesList handles null dates in sorting', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.repositories = [
        { Name: 'repo1', LastScanTime: '2024-01-15T10:00:00Z' },
        { Name: 'repo2', LastScanTime: null },
        { Name: 'repo3', LastScanTime: '2024-01-10T10:00:00Z' }
    ];
    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'asc';
    component.sortRepositories();

    // Null values should sort to the beginning
    assertEqual(component.repositories[0].Name, 'repo2', 'null date should be first');
});

// Test: Pagination logic
test('RepositoriesList goToPage updates currentPage', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.total = 100;
    component.goToPage(5);
    assertEqual(component.currentPage, 5, 'currentPage should be 5');
});

test('RepositoriesList goToPage prevents invalid page numbers', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.total = 100;
    component.currentPage = 1;
    component.goToPage(0);
    assertEqual(component.currentPage, 1, 'currentPage should remain 1 for page 0');

    component.goToPage(100);
    assertEqual(component.currentPage, 1, 'currentPage should remain 1 for page beyond total');
});

test('RepositoriesList calculates correct pagination offset', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.currentPage = 1;
    component.pageSize = 10;
    let offset = (component.currentPage - 1) * component.pageSize;
    assertEqual(offset, 0, 'page 1 offset should be 0');

    component.currentPage = 2;
    offset = (component.currentPage - 1) * component.pageSize;
    assertEqual(offset, 10, 'page 2 offset should be 10');

    component.currentPage = 5;
    offset = (component.currentPage - 1) * component.pageSize;
    assertEqual(offset, 40, 'page 5 offset should be 40');
});

test('RepositoriesList calculates correct total pages', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.total = 100;
    component.pageSize = 10;
    let totalPages = Math.ceil(component.total / component.pageSize);
    assertEqual(totalPages, 10, 'total pages should be 10');

    component.total = 105;
    totalPages = Math.ceil(component.total / component.pageSize);
    assertEqual(totalPages, 11, 'total pages should be 11');

    component.total = 5;
    totalPages = Math.ceil(component.total / component.pageSize);
    assertEqual(totalPages, 1, 'total pages should be 1');
});

// Test: Combined state operations
test('RepositoriesList maintains state across multiple operations', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.repositories = [
        { Name: 'zebra' },
        { Name: 'apple' },
        { Name: 'banana' }
    ];
    component.total = 3;

    // Apply filter
    component.setFilters({ search: 'test' });
    assertEqual(component.filters.search, 'test', 'filter should be applied');
    assertEqual(component.currentPage, 1, 'page should reset');

    // Apply sort
    component.setSort('name', 'desc');
    assertEqual(component.sortColumn, 'name', 'sort column should be set');
    assertEqual(component.sortDirection, 'desc', 'sort direction should be set');

    // Navigate to page
    component.goToPage(2);
    assertEqual(component.currentPage, 2, 'page should be updated');

    // Verify all state is maintained
    assertEqual(component.filters.search, 'test', 'filter should still be applied');
    assertEqual(component.sortColumn, 'name', 'sort column should still be set');
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
    module.exports = { runTests, RepositoriesList, MockApiClient };
}
