/**
 * Test Runner for UI Component Tests
 * Runs all component tests and reports results
 */

// Simple test runner that works in Node.js environment
async function runAllTests() {
    const results = {
        suites: [],
        totalTests: 0,
        totalPassed: 0,
        totalFailed: 0
    };

    // Import test modules
    try {
        // Dynamic import for Node.js environment
        const repositoriesListTests = await import('./repositories-list.test.js');
        const repositoryDetailTests = await import('./repository-detail.test.js');

        // Run RepositoriesList tests
        console.log('\n=== Running RepositoriesList Tests ===\n');
        const repositoriesListResults = await repositoriesListTests.runTests();
        results.suites.push({
            name: 'RepositoriesList',
            ...repositoriesListResults
        });
        results.totalTests += repositoriesListResults.results.length;
        results.totalPassed += repositoriesListResults.passed;
        results.totalFailed += repositoriesListResults.failed;

        // Print RepositoriesList results
        repositoriesListResults.results.forEach(result => {
            const icon = result.status === 'PASS' ? '✓' : '✗';
            console.log(`${icon} ${result.name}`);
            if (result.error) {
                console.log(`  Error: ${result.error}`);
            }
        });

        // Run RepositoryDetail tests
        console.log('\n=== Running RepositoryDetail Tests ===\n');
        const repositoryDetailResults = await repositoryDetailTests.runTests();
        results.suites.push({
            name: 'RepositoryDetail',
            ...repositoryDetailResults
        });
        results.totalTests += repositoryDetailResults.results.length;
        results.totalPassed += repositoryDetailResults.passed;
        results.totalFailed += repositoryDetailResults.failed;

        // Print RepositoryDetail results
        repositoryDetailResults.results.forEach(result => {
            const icon = result.status === 'PASS' ? '✓' : '✗';
            console.log(`${icon} ${result.name}`);
            if (result.error) {
                console.log(`  Error: ${result.error}`);
            }
        });

        // Print summary
        console.log('\n=== Test Summary ===\n');
        console.log(`Total Tests: ${results.totalTests}`);
        console.log(`Passed: ${results.totalPassed}`);
        console.log(`Failed: ${results.totalFailed}`);

        if (results.totalFailed === 0) {
            console.log('\n✓ All tests passed!');
            process.exit(0);
        } else {
            console.log(`\n✗ ${results.totalFailed} test(s) failed`);
            process.exit(1);
        }

    } catch (error) {
        console.error('Error running tests:', error);
        process.exit(1);
    }
}

// Run tests if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
    runAllTests();
}

export { runAllTests };
