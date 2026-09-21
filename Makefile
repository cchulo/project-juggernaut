SHELL := /bin/bash
GO ?= go
BIN ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/cchulo/project-juggernaut/internal/version.Version=$(VERSION)
IMAGE_REGISTRY ?= ghcr.io/cchulo
IMAGE_TAG ?= $(VERSION)

BINARIES := juggernaut juggernaut-gateway juggernaut-controller juggernaut-wrapper juggernaut-egress

.PHONY: all build $(BINARIES) test test-unit test-integration test-race lint fmt vet tidy validate-example generate images ui helm-lint helm-template kustomize-build clean

all: build

build: $(BINARIES)

$(BINARIES):
	@mkdir -p $(BIN)
	@if [ -d cmd/$@ ]; then CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $(BIN)/$@ ./cmd/$@; else echo "skip $@ (not scaffolded yet)"; fi

# Unit tests plus the in-process end-to-end tests (real wrapper binary, real
# stdio MCP server, real gateway; no docker, no cluster, no identity provider).
test:
	$(GO) test ./...

# Only the fast, hermetic packages: everything except the end-to-end suite.
test-unit:
	$(GO) test $(shell $(GO) list ./... | grep -v /internal/integration)

# Environment-dependent tests (docker daemon, locally built images); they
# skip themselves when the environment is missing.
test-integration:
	$(GO) test -tags integration -count=1 ./internal/integration/...

# The concurrency-heavy packages under the race detector.
test-race:
	$(GO) test -race -count=1 ./internal/wrapper/... ./internal/router/... ./internal/gateway/... ./internal/mcpproxy/... ./internal/egress/... ./internal/integration/...

fmt:
	gofmt -l -w $(shell find . -name '*.go' -not -path './vendor/*')

vet:
	$(GO) vet ./...

lint:
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || echo "golangci-lint not installed; running go vet"; $(GO) vet ./...

tidy:
	$(GO) mod tidy

validate-example: juggernaut
	$(BIN)/juggernaut validate -f examples/juggernaut.yaml

generate:
	@command -v controller-gen >/dev/null || $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
	controller-gen object crd paths=./api/... output:crd:artifacts:config=deploy/crds

images:
	@for b in $(BINARIES); do \
	  if [ -f images/$$b/Dockerfile ]; then docker build -f images/$$b/Dockerfile -t $(IMAGE_REGISTRY)/$$b:$(IMAGE_TAG) . ; fi; \
	done

ui:
	cd ui/admin && npm ci && npm run build

helm-lint:
	helm lint charts/juggernaut --set config="$$(cat examples/juggernaut.yaml)"

helm-template:
	helm template juggernaut charts/juggernaut --namespace juggernaut-system --set-file config=deploy/kustomize/base/juggernaut.yaml --set keycloak.enabled=true > /dev/null

kustomize-build:
	kubectl kustomize deploy/kustomize/overlays/kind > /dev/null

clean:
	rm -rf $(BIN)
