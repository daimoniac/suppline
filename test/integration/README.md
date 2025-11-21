# Integration Tests

This directory contains integration tests that verify the components work together correctly.

## Prerequisites

- Docker and Docker Compose installed
- Go 1.21 or later
- Make (optional, but recommended)

## Running Integration Tests

### Using Make (Recommended)

```bash
# Run integration tests (automatically starts/stops Docker services)
make test-integration

# Or manually control Docker services
make docker-up          # Start services
make test-integration   # Run tests
make docker-down        # Stop services
```

### Manual Execution

1. Start the required services:
```bash
docker-compose -f docker-compose.test.yml up -d
```

2. Wait for services to be ready (about 30 seconds for Trivy to download databases)

3. Run the tests:
```bash
INTEGRATION_TEST=true TRIVY_SERVER_ADDR=localhost:4954 go test -v -timeout 10m ./test/integration/...
```

4. Stop the services:
```bash
docker-compose -f docker-compose.test.yml down -v
```

## Test Coverage

The integration tests cover:

### 0. Optimized Attestation Flow (Task 3)
- **SBOM Generation Once**: Verifies SBOM is generated only once with Trivy
- **Pre-generated SBOM Attestation**: Creates attestation using pre-generated SBOM data without redundant Trivy invocations
- **SBOM Data Validation**: Validates SBOM format and JSON structure before attestation
- **Error Handling**: Tests rejection of nil, empty, and malformed SBOM data
- **End-to-End Flow**: Complete workflow with SBOM and vulnerability attestations using only 2 Trivy invocations
- **Digest Resolution**: Automatically resolves image tags to digests to avoid cosign warnings
- **Local Registry Integration**: Uses local test registry (localhost:5000) for complete end-to-end attestation testing
- **Attestation Verification**: Verifies created attestations using cosign with the public key

### 1. Trivy Scanner Integration
- Health check connectivity
- Vulnerability scanning with real images
- SBOM generation in CycloneDX format
- Proper parsing of scan results

### 2. State Store Integration
- Recording scan results with vulnerabilities
- Retrieving scan history
- Querying vulnerabilities with filters
- Managing tolerated CVEs
- Identifying images due for rescanning

### 3. Task Queue Integration
- Enqueuing and dequeuing tasks
- Task deduplication
- Task completion and failure handling
- Queue depth tracking

### 4. Policy Engine Integration
- Policy evaluation with no vulnerabilities
- Policy failure with critical vulnerabilities
- CVE toleration handling
- Expired toleration detection
- Expiring toleration warnings

### 5. End-to-End Workflow
- Complete scan workflow from queue to storage
- Integration of scanner, queue, and state store
- Realistic image scanning scenarios

### 6. Complete Worker Workflow (Task 8.2)
- **Clean Image Workflow**: Tests scanning, SBOM generation, policy evaluation, and state recording for images with minimal vulnerabilities
- **Vulnerable Image Workflow**: Tests handling of images with critical vulnerabilities, ensuring attestations are created
- **Tolerated CVEs Workflow**: Tests policy evaluation with CVE tolerations, verifying that tolerated critical CVEs allow policy to pass
- **Rescan Workflow**: Tests the rescan scenario where a previously passing image now fails policy, including alert detection

## Test Services

### Trivy Server
- **Port**: 4954
- **Purpose**: Vulnerability scanning and SBOM generation
- **Image**: aquasec/trivy:latest
- **Startup time**: ~30 seconds (downloads vulnerability database)

### Test Registry
- **Port**: 5000
- **Purpose**: Local Docker registry for testing image operations and attestations
- **Image**: registry:2
- **Startup time**: ~5 seconds
- **Usage**: Tests automatically push images to `localhost:5000/test/*` for attestation testing

## Environment Variables

- `INTEGRATION_TEST`: Set to "true" to enable integration tests (default: disabled)
- `TRIVY_SERVER_ADDR`: Trivy server address (default: localhost:4954)
- `ATTESTATION_KEY_PATH`: Path to cosign private key for attestation tests (default: ../../keys/cosign.key)

## Troubleshooting

### Tests fail with "connection refused"
- Ensure Docker services are running: `docker-compose -f docker-compose.test.yml ps`
- Check service logs: `make docker-logs`
- Wait longer for Trivy to initialize (first run downloads databases)

### Trivy server is slow
- First run downloads vulnerability databases (~500MB)
- Subsequent runs use cached data
- Check Trivy logs: `docker logs trivy-server`

### Tests timeout
- Increase timeout: `go test -timeout 15m ./test/integration/...`
- Check if Trivy server is responding: `curl http://localhost:4954/healthz`

## Adding New Tests

1. Create a new test function in `integration_test.go`
2. Use the existing component initialization patterns
3. Clean up resources in defer statements
4. Use descriptive test names and subtests
5. Log important information for debugging

Example:
```go
func TestNewFeature(t *testing.T) {
    // Setup
    ctx := context.Background()
    
    t.Run("SubTest", func(t *testing.T) {
        // Test logic
        
        // Assertions
        if got != want {
            t.Errorf("Expected %v, got %v", want, got)
        }
    })
}
```

## CI/CD Integration

To run integration tests in CI/CD:

```yaml
# Example GitHub Actions
- name: Start services
  run: docker-compose -f docker-compose.test.yml up -d

- name: Wait for services
  run: sleep 30

- name: Run integration tests
  run: INTEGRATION_TEST=true go test -v -timeout 10m ./test/integration/...
  
- name: Stop services
  run: docker-compose -f docker-compose.test.yml down -v
  if: always()
```
