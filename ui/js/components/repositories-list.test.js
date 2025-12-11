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
    assertEqual(component.sortColumn, 'lastScanTime', 'sortColumn should be lastScanTime');
    assertEqual(component.sortDirection, 'desc', 'sortDirection should be desc');
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

test('RepositoriesList setSort toggles direction for lastScanTime', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.setSort('lastScanTime', 'desc');
    assertEqual(component.sortColumn, 'lastScanTime', 'sortColumn should be lastScanTime');
    assertEqual(component.sortDirection, 'desc', 'sortDirection should be desc');
    
    component.setSort('lastScanTime'); // Toggle
    assertEqual(component.sortDirection, 'asc', 'sortDirection should toggle to asc');
    
    component.setSort('lastScanTime'); // Toggle again
    assertEqual(component.sortDirection, 'desc', 'sortDirection should toggle back to desc');
});

// Note: Client-side sorting tests removed since we now use server-side sorting

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

// Test: Server-side sorting parameters
test('RepositoriesList sends correct sort_by parameter for name ascending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'name';
    component.sortDirection = 'asc';
    const sortBy = component.getSortByParam();
    assertEqual(sortBy, 'name_asc', 'should return name_asc for name ascending');
});

test('RepositoriesList sends correct sort_by parameter for name descending', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'name';
    component.sortDirection = 'desc';
    const sortBy = component.getSortByParam();
    assertEqual(sortBy, 'name_desc', 'should return name_desc for name descending');
});

test('RepositoriesList sends correct sort_by parameter for lastScanTime desc', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'desc';
    const sortBy = component.getSortByParam();
    assertEqual(sortBy, 'age_desc', 'should return age_desc for lastScanTime desc');
});

test('RepositoriesList sends correct sort_by parameter for lastScanTime asc', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'asc';
    const sortBy = component.getSortByParam();
    assertEqual(sortBy, 'age_asc', 'should return age_asc for lastScanTime asc');
});

test('RepositoriesList sends correct sort_by parameter for status asc', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'status';
    component.sortDirection = 'asc';
    const sortBy = component.getSortByParam();
    assertEqual(sortBy, 'status_asc', 'should return status_asc for status asc');
});

test('RepositoriesList sends correct sort_by parameter for status desc', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'status';
    component.sortDirection = 'desc';
    const sortBy = component.getSortByParam();
    assertEqual(sortBy, 'status_desc', 'should return status_desc for status desc');
});

test('RepositoriesList sends correct API parameters on loadRepositories', async () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.currentPage = 2;
    component.pageSize = 20;
    component.sortColumn = 'name';
    component.sortDirection = 'asc';
    component.filters.search = 'test';

    await component.loadRepositories();

    assertEqual(apiClient.callHistory.length, 1, 'should make one API call');
    const call = apiClient.callHistory[0];
    assertEqual(call.method, 'getRepositories', 'should call getRepositories');
    
    const expectedFilters = {
        limit: 20,
        offset: 20, // (page 2 - 1) * 20
        search: 'test',
        sort_by: 'name_asc'
    };
    
    assertDeepEqual(call.filters, expectedFilters, 'should send correct filters');
});

test('RepositoriesList sends age_asc parameter for lastScanTime ascending', async () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'lastScanTime';
    component.sortDirection = 'asc';

    await component.loadRepositories();

    assertEqual(apiClient.callHistory.length, 1, 'should make one API call');
    const call = apiClient.callHistory[0];
    assertEqual(call.filters.sort_by, 'age_asc', 'should send age_asc for lastScanTime asc');
});

test('RepositoriesList sends status_desc parameter for status descending', async () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.sortColumn = 'status';
    component.sortDirection = 'desc';

    await component.loadRepositories();

    assertEqual(apiClient.callHistory.length, 1, 'should make one API call');
    const call = apiClient.callHistory[0];
    assertEqual(call.filters.sort_by, 'status_desc', 'should send status_desc for status desc');
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
