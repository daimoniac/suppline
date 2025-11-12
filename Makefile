.PHONY: help test test-unit test-integration docker-up docker-down docker-logs clean build

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	go build -o suppline ./cmd/suppline

test: test-unit ## Run all tests

test-unit: ## Run unit tests
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./internal/...

test-integration: docker-up ## Run integration tests
	@echo "Waiting for services to be ready..."
	@sleep 30
	INTEGRATION_TEST=true TRIVY_SERVER_ADDR=localhost:4954 ATTESTATION_KEY_PATH=$(PWD)/keys/cosign.key go test -v -timeout 10m ./test/integration/...
	@$(MAKE) docker-down

docker-up: ## Start Docker Compose services for testing
	docker compose -f docker-compose.test.yml up -d
	@echo "Waiting for services to start..."
	@sleep 5

docker-down: ## Stop Docker Compose services
	docker compose -f docker-compose.test.yml down -v

docker-logs: ## Show Docker Compose logs
	docker compose -f docker-compose.test.yml logs -f

clean: ## Clean build artifacts and test databases
	rm -f suppline
	rm -f *.db
	rm -f coverage.txt
	rm -rf test/*.db

lint: ## Run linters
	golangci-lint run ./...

fmt: ## Format code
	go fmt ./...
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

deps: ## Download dependencies
	go mod download
	go mod tidy

# Development helpers
dev-setup: deps ## Set up development environment
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

run: build ## Build and run the application
	./suppline

# Docker targets
docker-build: ## Build Docker image
	docker build -t suppline:latest -f Dockerfile .

docker-build-trivy: ## Build Trivy server Docker image
	docker build -t trivy-server:latest -f Dockerfile.trivy .

docker-run: ## Run application with Docker Compose
	docker compose up -d

docker-stop: ## Stop Docker Compose
	docker compose down

docker-restart: ## Restart Docker Compose
	docker compose restart

docker-clean: ## Clean Docker resources
	docker compose down -v
	docker rmi suppline:latest trivy-server:latest || true

# Kubernetes targets
k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -k deploy/kubernetes/

k8s-delete: ## Delete from Kubernetes
	kubectl delete -k deploy/kubernetes/

k8s-logs: ## View Kubernetes logs
	kubectl logs -n suppline -l app=suppline -f

k8s-status: ## Check Kubernetes deployment status
	kubectl get all -n suppline

k8s-describe: ## Describe Kubernetes resources
	kubectl describe deployment suppline -n suppline

k8s-restart: ## Restart Kubernetes deployment
	kubectl rollout restart deployment/suppline -n suppline

k8s-port-forward: ## Port forward to access services locally
	@echo "Forwarding ports: API=8080, Metrics=9090, Health=8081"
	kubectl port-forward -n suppline svc/suppline 8080:8080 9090:9090 8081:8081

# Release targets
release-build: ## Build release binaries for multiple platforms
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o dist/suppline-linux-amd64 ./cmd/suppline
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -o dist/suppline-linux-arm64 ./cmd/suppline
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o dist/suppline-darwin-amd64 ./cmd/suppline
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o dist/suppline-darwin-arm64 ./cmd/suppline

# API Documentation targets
swagger: ## Generate Swagger/OpenAPI documentation
	@echo "Generating Swagger documentation..."
	@swag init -g internal/api/api.go -o docs/swagger --parseDependency --parseInternal
	@echo "✅ Swagger docs generated at docs/swagger/"
	@echo "📖 View at http://localhost:8080/swagger/ (when server is running)"

swagger-install: ## Install swag CLI tool
	@echo "Installing swag CLI tool..."
	@go install github.com/swaggo/swag/cmd/swag@latest
	@echo "✅ Swag installed. Run 'make swagger' to generate docs"

swagger-verify: ## Verify docs are up-to-date (for CI)
	@echo "Verifying Swagger docs are up-to-date..."
	@swag init -g internal/api/api.go -o docs/swagger --parseDependency --parseInternal
	@if [ -n "$$(git status --porcelain docs/swagger/)" ]; then \
		echo "❌ Swagger docs are out of sync! Run 'make swagger' and commit changes."; \
		git diff docs/swagger/; \
		exit 1; \
	else \
		echo "✅ Swagger docs are up-to-date"; \
	fi
