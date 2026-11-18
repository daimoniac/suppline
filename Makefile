.PHONY: help test test-unit test-integration test-all lint docker-up docker-down docker-logs clean build ui

VERSION ?= dev

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: swagger ui ## Build the binary with the embedded web UI
	go build -tags embedui -ldflags="-X github.com/daimoniac/suppline/internal/version.Version=$(VERSION)" -o suppline ./cmd/suppline

ui: ## Build the web UI into ui/dist (embedded by `make build`)
	cd ui && npm ci && npm run build

test: test-unit ## Run unit tests (default)

test-unit: ## Run unit tests (same as CI)
	go test -race ./internal/...
	cd clusterstate-agent && go test -race ./...

test-integration: ## Run integration tests (needs a Trivy server; see test/integration/README.md)
	INTEGRATION_TEST=true TRIVY_SERVER_ADDR=$${TRIVY_SERVER_ADDR:-localhost:4954} go test -v -timeout 10m ./test/integration/...

test-all: test-unit test-integration ## Run unit and integration tests

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
	rm -rf build/ ui/dist

# Pinned to the CI version (.github/workflows/test.yml) and built with the local
# Go toolchain, so it can read this module's Go version.
GOLANGCI_LINT_VERSION ?= v2.15.0
GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: ## Run linters (same version as CI)
	$(GOLANGCI_LINT) run --timeout=5m ./...
	cd clusterstate-agent && $(GOLANGCI_LINT) run --timeout=5m ./...

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
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

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
	@echo "Forwarding ports: UI/API=8080, metrics+health=9090"
	kubectl port-forward -n suppline svc/suppline 8080:8080 9090:9090

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
release-build: swagger ui ## Build release binaries for multiple platforms
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -tags embedui -o dist/suppline-linux-amd64 ./cmd/suppline
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -tags embedui -o dist/suppline-linux-arm64 ./cmd/suppline
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -tags embedui -o dist/suppline-darwin-amd64 ./cmd/suppline
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -tags embedui -o dist/suppline-darwin-arm64 ./cmd/suppline

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

