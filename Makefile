.PHONY: help test test-unit test-integration test-auth test-all docker-up docker-down docker-logs clean build

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	go build -o suppline ./cmd/suppline

build-ui: ## Build the UI Docker image
	@echo "Building UI Docker image..."
	docker build -t suppline-ui:latest -f ui/Dockerfile ./ui
	@echo "✅ UI image built successfully"

build-all: ## Build all components (backend + UI)
	@echo "Building all components..."
	@$(MAKE) build
	@$(MAKE) build-ui
	@echo "✅ All components built successfully"

test: test-unit ## Run unit tests (default)

test-unit: ## Run unit tests
	@./scripts/test.sh unit

test-integration: ## Run integration tests with Docker Compose
	@./scripts/test.sh integration

test-auth: ## Test Trivy and Cosign authentication
	@./scripts/test.sh auth

test-all: ## Run all tests (unit, auth, integration)
	@./scripts/test.sh all

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
	rm -rf build/

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

docker-build-ui: ## Build UI Docker image
	docker build -t suppline-ui:latest -f ui/Dockerfile ./ui

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

# Helm targets
helm-package: ## Package Helm chart
	@echo "Packaging Helm chart..."
	@mkdir -p build/charts
	helm package charts/suppline -d build/charts
	@echo "✅ Helm chart packaged successfully"
	@ls -lh build/charts/

helm-lint: ## Lint Helm chart
	@echo "Linting Helm chart..."
	helm lint charts/suppline
	@echo "✅ Helm chart linted successfully"

helm-template: ## Generate Kubernetes manifests from Helm chart
	@echo "Generating Kubernetes manifests from Helm chart..."
	helm template suppline charts/suppline

helm-install: ## Install Helm chart to current Kubernetes context
	@echo "Installing Helm chart..."
	helm upgrade --install suppline charts/suppline --namespace suppline --create-namespace
	@echo "✅ Helm chart installed successfully"

helm-uninstall: ## Uninstall Helm chart
	@echo "Uninstalling Helm chart..."
	helm uninstall suppline --namespace suppline
	@echo "✅ Helm chart uninstalled successfully"

# Release targets
release-build: ## Build release binaries for multiple platforms
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o dist/suppline-linux-amd64 ./cmd/suppline
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -o dist/suppline-linux-arm64 ./cmd/suppline
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o dist/suppline-darwin-amd64 ./cmd/suppline
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o dist/suppline-darwin-arm64 ./cmd/suppline

# API Documentation targets
swagger: ## Generate Swagger/OpenAPI documentation
	@echo "Generating Swagger documentation..."
	@mkdir -p build/swagger
	@swag init -g internal/api/api.go -o build/swagger --parseDependency --parseInternal
	@echo "✅ Swagger docs generated at build/swagger/"
	@echo "📖 View at http://localhost:8080/swagger/ (when server is running)"

swagger-install: ## Install swag CLI tool
	@echo "Installing swag CLI tool..."
	@go install github.com/swaggo/swag/cmd/swag@latest
	@echo "✅ Swag installed. Run 'make swagger' to generate docs"

