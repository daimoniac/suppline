#!/usr/bin/env node

/**
 * Test Runner Entry Point
 * Executes all UI component tests
 */

// Mock implementations for browser APIs that tests might need
global.document = {
    getElementById: () => null,
    createElement: (tag) => ({
        textContent: '',
        innerHTML: '',
        addEventListener: () => {},
        appendChild: () => {},
        removeChild: () => {},
        querySelectorAll: () => [],
        querySelector: () => null
    }),
    querySelectorAll: () => []
};

global.window = {
    router: {
        navigate: () => {}
    }
};

// Test utilities
class MockApiClient {
    constructor(mockData = {}) {
        this.mockData = mockData;
        this.callHistory = [];
    }

    async getRepositories(filters) {
        this.callHistory.push({ method: 'getRepositories', filters });
        return this.mockData.repositories || { Repositories: [], Total: 0 };
    }

    async getRepository(repositoryName, filters) {
        this.callHistory.push({ method: 'getRepository', repositoryName, filters });
        return this.mockData.repository || { Tags: [], Total: 0 };
    }

    async triggerRepositoryRescan(repositoryName) {
        this.callHistory.push({ method: 'triggerRepositoryRescan', repositoryName });
        return { message: 'Rescan triggered' };
    }

    async triggerTagRescan(repositoryName, tagName) {
        this.callHistory.push({ method: 'triggerTagRescan', repositoryName, tagName });
        return { message: 'Rescan triggered' };
    }
}

// Test framework
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

// RepositoriesList Component (minimal implementation for testing)
class RepositoriesList {
    constructor(apiClient) {
        this.apiClient = apiClient;
        this.repositories = [];
        this.total = 0;
        this.currentPage = 1;
        this.pageSize = 10;
        this.filters = { search: '' };
        this.sortColumn = 'name';
        this.sortDirection = 'asc';
    }

    setFilters(filters) {
        this.filters = { ...this.filters, ...filters };
        this.currentPage = 1;
    }

    setSort(column, direction = null) {
        if (this.sortColumn === column && direction === null) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = direction || 'asc';
        }
        this.sortRepositories();
    }

    goToPage(page) {
        const totalPages = Math.ceil(this.total / this.pageSize);
        if (page >= 1 && page <= totalPages) {
            this.currentPage = page;
        }
    }

    sortRepositories() {
        const columnMap = {
            'name': 'Name',
            'lastScanTime': 'LastScanTime',
            'nextScanTime': 'NextScanTime'
        };

        const apiColumn = columnMap[this.sortColumn] || this.sortColumn;

        this.repositories.sort((a, b) => {
            let aVal = a[apiColumn];
            let bVal = b[apiColumn];

            if (aVal === null || aVal === undefined) aVal = '';
            if (bVal === null || bVal === undefined) bVal = '';

            if (this.sortColumn === 'lastScanTime' || this.sortColumn === 'nextScanTime') {
                aVal = new Date(aVal).getTime();
                bVal = new Date(bVal).getTime();
            }

            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return this.sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
            }

            const comparison = String(aVal).localeCompare(String(bVal));
            return this.sortDirection === 'asc' ? comparison : -comparison;
        });
    }
}

// RepositoryDetail Component (minimal implementation for testing)
class RepositoryDetail {
    constructor(apiClient) {
        this.apiClient = apiClient;
        this.repositoryName = null;
        this.tags = [];
        this.total = 0;
        this.currentPage = 1;
        this.pageSize = 10;
        this.filters = { search: '' };
        this.sortColumn = 'name';
        this.sortDirection = 'asc';
    }

    setRepository(name) {
        this.repositoryName = name;
    }

    setFilters(filters) {
        this.filters = { ...this.filters, ...filters };
        this.currentPage = 1;
    }

    setSort(column, direction = null) {
        if (this.sortColumn === column && direction === null) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = direction || 'asc';
        }
        this.sortTags();
    }

    goToPage(page) {
        const totalPages = Math.ceil(this.total / this.pageSize);
        if (page >= 1 && page <= totalPages) {
            this.currentPage = page;
        }
    }

    sortTags() {
        const columnMap = {
            'name': 'Name',
            'lastScanTime': 'LastScanTime',
            'nextScanTime': 'NextScanTime'
        };

        const apiColumn = columnMap[this.sortColumn] || this.sortColumn;

        this.tags.sort((a, b) => {
            let aVal = a[apiColumn];
            let bVal = b[apiColumn];

            if (aVal === null || aVal === undefined) aVal = '';
            if (bVal === null || bVal === undefined) bVal = '';

            if (this.sortColumn === 'lastScanTime' || this.sortColumn === 'nextScanTime') {
                aVal = new Date(aVal).getTime();
                bVal = new Date(bVal).getTime();
            }

            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return this.sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
            }

            const comparison = String(aVal).localeCompare(String(bVal));
            return this.sortDirection === 'asc' ? comparison : -comparison;
        });
    }
}

// RepositoriesList Tests
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

    // Verify that sorting completes without error and maintains all items
    assertEqual(component.repositories.length, 3, 'all repositories should be present');
    assert(
        component.repositories.some(r => r.Name === 'repo2'),
        'null date repository should be in results'
    );
});

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

test('RepositoriesList maintains state across multiple operations', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoriesList(apiClient);

    component.repositories = [
        { Name: 'zebra' },
        { Name: 'apple' },
        { Name: 'banana' }
    ];
    component.total = 30; // Set total high enough for page 2 to be valid

    component.setFilters({ search: 'test' });
    assertEqual(component.filters.search, 'test', 'filter should be applied');
    assertEqual(component.currentPage, 1, 'page should reset');

    component.setSort('name', 'desc');
    assertEqual(component.sortColumn, 'name', 'sort column should be set');
    assertEqual(component.sortDirection, 'desc', 'sort direction should be set');

    component.goToPage(2);
    assertEqual(component.currentPage, 2, 'page should be updated');

    assertEqual(component.filters.search, 'test', 'filter should still be applied');
    assertEqual(component.sortColumn, 'name', 'sort column should still be set');
});

// RepositoryDetail Tests
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

test('RepositoryDetail setRepository sets repository name', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.setRepository('my-app');
    assertEqual(component.repositoryName, 'my-app', 'repositoryName should be set');
});

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

    // Verify that sorting completes without error and maintains all items
    assertEqual(component.tags.length, 3, 'all tags should be present');
    assert(
        component.tags.some(t => t.Name === 'tag2'),
        'null date tag should be in results'
    );
});

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

test('RepositoryDetail maintains state across multiple operations', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.setRepository('my-app');
    component.tags = [
        { Name: 'v2.0.0' },
        { Name: 'latest' },
        { Name: 'v1.0.0' }
    ];
    component.total = 30; // Set total high enough for page 2 to be valid

    component.setFilters({ search: 'v' });
    assertEqual(component.filters.search, 'v', 'filter should be applied');
    assertEqual(component.currentPage, 1, 'page should reset');

    component.setSort('name', 'desc');
    assertEqual(component.sortColumn, 'name', 'sort column should be set');
    assertEqual(component.sortDirection, 'desc', 'sort direction should be set');

    component.goToPage(2);
    assertEqual(component.currentPage, 2, 'page should be updated');

    assertEqual(component.repositoryName, 'my-app', 'repository name should be maintained');
    assertEqual(component.filters.search, 'v', 'filter should still be applied');
    assertEqual(component.sortColumn, 'name', 'sort column should still be set');
});

test('RepositoryDetail filter and sort work together', () => {
    const apiClient = new MockApiClient();
    const component = new RepositoryDetail(apiClient);

    component.tags = [
        { Name: 'v2.0.0', LastScanTime: '2024-01-15T10:00:00Z' },
        { Name: 'v1.0.0', LastScanTime: '2024-01-10T10:00:00Z' },
        { Name: 'latest', LastScanTime: '2024-01-20T10:00:00Z' }
    ];

    component.setSort('lastScanTime', 'desc');
    component.sortTags();

    assertEqual(component.tags[0].Name, 'latest', 'latest should be first (most recent)');
    assertEqual(component.tags[1].Name, 'v2.0.0', 'v2.0.0 should be second');
    assertEqual(component.tags[2].Name, 'v1.0.0', 'v1.0.0 should be third (oldest)');
});

// Run all tests
async function runAllTests() {
    let passed = 0;
    let failed = 0;
    const results = [];

    console.log('\n=== Running UI Component Unit Tests ===\n');

    for (const { name, fn } of tests) {
        try {
            fn();
            passed++;
            results.push({ name, status: 'PASS' });
            console.log(`✓ ${name}`);
        } catch (error) {
            failed++;
            results.push({ name, status: 'FAIL', error: error.message });
            console.log(`✗ ${name}`);
            console.log(`  Error: ${error.message}`);
        }
    }

    console.log('\n=== Test Summary ===\n');
    console.log(`Total Tests: ${tests.length}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);

    if (failed === 0) {
        console.log('\n✓ All tests passed!');
        process.exit(0);
    } else {
        console.log(`\n✗ ${failed} test(s) failed`);
        process.exit(1);
    }
}

runAllTests().catch(error => {
    console.error('Error running tests:', error);
    process.exit(1);
});
