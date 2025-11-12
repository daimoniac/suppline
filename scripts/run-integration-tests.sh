#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting integration test environment...${NC}"

# Start Docker Compose services
echo "Starting Docker services..."
docker compose -f docker-compose.test.yml up -d

# Function to check if a service is ready
check_service() {
    local service=$1
    local max_attempts=30
    local attempt=1

    echo -n "Waiting for $service to be ready"
    while [ $attempt -le $max_attempts ]; do
        if docker compose -f docker-compose.test.yml ps | grep -q "$service.*healthy\|Up"; then
            echo -e " ${GREEN}✓${NC}"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo -e " ${RED}✗${NC}"
    echo -e "${RED}$service failed to become ready${NC}"
    return 1
}

# Wait for services to be ready
check_service "trivy-server"
check_service "test-registry"

# Additional wait for Trivy to download databases (first run)
echo "Waiting for Trivy to initialize (downloading vulnerability databases)..."
sleep 10

# Check Trivy health
echo "Checking Trivy health..."
if docker exec trivy-server trivy version > /dev/null 2>&1; then
    echo -e "${GREEN}Trivy is ready${NC}"
else
    echo -e "${YELLOW}Warning: Trivy health check failed, but continuing...${NC}"
fi

# Run integration tests
echo -e "${GREEN}Running integration tests...${NC}"
INTEGRATION_TEST=true TRIVY_SERVER_ADDR=localhost:4954 go test -v -timeout 10m ./test/integration/...

TEST_EXIT_CODE=$?

# Cleanup
echo -e "${GREEN}Cleaning up...${NC}"
docker compose -f docker-compose.test.yml down -v

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Integration tests passed!${NC}"
else
    echo -e "${RED}✗ Integration tests failed!${NC}"
fi

exit $TEST_EXIT_CODE
