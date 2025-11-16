#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default test mode
TEST_MODE="${1:-unit}"

print_header() {
    echo ""
    echo -e "${BLUE}===================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================${NC}"
    echo ""
}

print_test() {
    echo -e "${YELLOW}Test: $1${NC}"
    echo "-----------------------------------"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Function to check if a service is ready
check_service() {
    local service=$1
    local max_attempts=30
    local attempt=1

    echo -n "Waiting for $service to be ready"
    while [ $attempt -le $max_attempts ]; do
        if docker compose -f docker-compose.test.yml ps 2>/dev/null | grep -q "$service.*healthy\|Up"; then
            echo -e " ${GREEN}✓${NC}"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo -e " ${RED}✗${NC}"
    print_error "$service failed to become ready"
    return 1
}

# Unit tests
run_unit_tests() {
    print_header "Running Unit Tests"
    
    print_test "Scanner Package Tests"
    if go test -v ./internal/scanner 2>&1 | tee /tmp/scanner-test.log | grep -E "(PASS|FAIL)"; then
        print_success "Scanner unit tests passed"
    else
        print_error "Scanner unit tests failed"
        return 1
    fi
    echo ""
    
    print_test "Attestation Package Tests"
    if go test -v ./internal/attestation 2>&1 | tee /tmp/attestation-test.log | grep -E "(PASS|FAIL)"; then
        print_success "Attestation unit tests passed"
    else
        print_error "Attestation unit tests failed"
        return 1
    fi
    echo ""
    
    print_test "Application Build"
    if go build -o /tmp/daimoniac/suppline-test ./cmd/daimoniac/suppline 2>&1; then
        print_success "Application builds successfully"
        rm -f /tmp/daimoniac/suppline-test
    else
        print_error "Application build failed"
        return 1
    fi
    echo ""
    
    print_success "All unit tests passed!"
}

# Integration tests with Docker Compose
run_integration_tests() {
    print_header "Running Integration Tests"
    
    # Check if docker-compose.test.yml exists
    if [ ! -f "docker-compose.test.yml" ]; then
        print_error "docker-compose.test.yml not found"
        print_info "Integration tests require docker-compose.test.yml"
        return 1
    fi
    
    print_info "Starting Docker Compose services..."
    docker compose -f docker-compose.test.yml up -d
    
    # Wait for services
    check_service "trivy-server" || return 1
    
    # Additional wait for Trivy to download databases
    print_info "Waiting for Trivy to initialize (downloading vulnerability databases)..."
    sleep 10
    
    # Check Trivy health
    print_test "Trivy Health Check"
    if docker exec trivy-server trivy version > /dev/null 2>&1; then
        print_success "Trivy is ready"
    else
        print_error "Trivy health check failed"
    fi
    echo ""
    
    # Run Go integration tests
    print_test "Go Integration Tests"
    if INTEGRATION_TEST=true TRIVY_SERVER_ADDR=localhost:4954 go test -v -timeout 10m ./test/integration/... 2>&1 | tee /tmp/integration-test.log; then
        print_success "Integration tests passed"
    else
        print_error "Integration tests failed"
        docker compose -f docker-compose.test.yml down -v
        return 1
    fi
    echo ""
    
    # Cleanup
    print_info "Cleaning up Docker services..."
    docker compose -f docker-compose.test.yml down -v
    
    print_success "All integration tests passed!"
}

# Manual Trivy authentication test
run_trivy_auth_test() {
    print_header "Testing Trivy Authentication"
    
    if [ ! -f "daimoniac/suppline.yml" ]; then
        print_error "daimoniac/suppline.yml not found"
        return 1
    fi
    
    # Test with trivy registry login (new approach)
    print_test "Trivy Registry Login"
    
    # Extract credentials from daimoniac/suppline.yml
    REGISTRY=$(grep -A 3 "^creds:" daimoniac/suppline.yml | grep "registry:" | head -1 | awk '{print $2}')
    USERNAME=$(grep -A 3 "^creds:" daimoniac/suppline.yml | grep "user:" | head -1 | awk '{print $2}')
    PASSWORD=$(grep -A 3 "^creds:" daimoniac/suppline.yml | grep "pass:" | head -1 | awk '{print $2}')
    
    if [ -z "$REGISTRY" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        print_error "Could not extract credentials from daimoniac/suppline.yml"
        return 1
    fi
    
    print_info "Logging into $REGISTRY..."
    if trivy registry login "$REGISTRY" --username "$USERNAME" --password "$PASSWORD" 2>&1; then
        print_success "Trivy login successful"
    else
        print_error "Trivy login failed"
        return 1
    fi
    echo ""
    
    # Test scanning a private image
    print_test "Scanning Private Image"
    PRIVATE_IMAGE=$(grep "target:" daimoniac/suppline.yml | head -1 | awk '{print $2}')
    
    if [ -z "$PRIVATE_IMAGE" ]; then
        print_info "No private image found in daimoniac/suppline.yml, using public image"
        PRIVATE_IMAGE="alpine:3.19"
    else
        # Add a tag if not present
        if [[ ! "$PRIVATE_IMAGE" =~ ":" ]]; then
            PRIVATE_IMAGE="${PRIVATE_IMAGE}:latest"
        fi
    fi
    
    print_info "Scanning: $PRIVATE_IMAGE"
    if timeout 60 trivy image --format json --quiet --scanners vuln "$PRIVATE_IMAGE" > /tmp/trivy-auth-test.json 2>&1; then
        VULN_COUNT=$(jq -r '[.Results[]?.Vulnerabilities? | length] | add // 0' /tmp/trivy-auth-test.json 2>/dev/null || echo "0")
        print_success "Trivy scan successful (found $VULN_COUNT vulnerabilities)"
    else
        print_error "Trivy scan failed"
        print_info "Error output:"
        head -20 /tmp/trivy-auth-test.json
        return 1
    fi
    echo ""
    
    print_success "Trivy authentication test passed!"
}

# Cosign authentication test
run_cosign_auth_test() {
    print_header "Testing Cosign Authentication"
    
    if [ ! -f "daimoniac/suppline.yml" ]; then
        print_error "daimoniac/suppline.yml not found"
        return 1
    fi
    
    print_test "Cosign Registry Login"
    
    # Extract credentials from daimoniac/suppline.yml
    REGISTRY=$(grep -A 3 "^creds:" daimoniac/suppline.yml | grep "registry:" | head -1 | awk '{print $2}')
    USERNAME=$(grep -A 3 "^creds:" daimoniac/suppline.yml | grep "user:" | head -1 | awk '{print $2}')
    PASSWORD=$(grep -A 3 "^creds:" daimoniac/suppline.yml | grep "pass:" | head -1 | awk '{print $2}')
    
    if [ -z "$REGISTRY" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        print_error "Could not extract credentials from daimoniac/suppline.yml"
        return 1
    fi
    
    print_info "Logging into $REGISTRY with cosign..."
    if cosign login "$REGISTRY" --username "$USERNAME" --password "$PASSWORD" 2>&1; then
        print_success "Cosign login successful"
    else
        print_error "Cosign login failed"
        return 1
    fi
    echo ""
    
    print_success "Cosign authentication test passed!"
}

# Show usage
show_usage() {
    echo "Usage: $0 [MODE]"
    echo ""
    echo "Modes:"
    echo "  unit          - Run unit tests only (default)"
    echo "  integration   - Run integration tests with Docker Compose"
    echo "  auth          - Test Trivy and Cosign authentication"
    echo "  all           - Run all tests"
    echo ""
    echo "Examples:"
    echo "  $0              # Run unit tests"
    echo "  $0 unit         # Run unit tests"
    echo "  $0 integration  # Run integration tests"
    echo "  $0 auth         # Test authentication"
    echo "  $0 all          # Run everything"
}

# Main execution
main() {
    case "$TEST_MODE" in
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration_tests
            ;;
        auth)
            run_trivy_auth_test
            run_cosign_auth_test
            ;;
        all)
            run_unit_tests
            echo ""
            run_trivy_auth_test
            echo ""
            run_cosign_auth_test
            echo ""
            if [ -f "docker-compose.test.yml" ]; then
                run_integration_tests
            else
                print_info "Skipping integration tests (docker-compose.test.yml not found)"
            fi
            ;;
        help|--help|-h)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown test mode: $TEST_MODE"
            echo ""
            show_usage
            exit 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        echo ""
        print_header "✓ All Tests Passed!"
        exit 0
    else
        echo ""
        print_header "✗ Tests Failed"
        exit 1
    fi
}

main
