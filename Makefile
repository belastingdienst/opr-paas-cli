GO := $(shell which go)
KUBECTL ?= kubectl

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	$(GO) vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter & yamllint
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: test
test: fmt vet gotest-coverage ## Run fmt, vet and tests with coverage.
	$(GO) test -v $$($(GO) list ./... | grep -v /e2e) -coverprofile=./cover.out -covermode=atomic -coverpkg=./...
	${GOTEST_COVERAGE} --config=./.testcoverage.yaml

.PHONY: build
build: ## Build the application.
	$(GO) build -o $(LOCALBIN)/kubectl-paas ./cmd/...

.PHONY: test-e2e
test-e2e: build ## Run e2e tests against whichever cluster KUBECONFIG points to (needs opr-paas CRDs installed).
	$(GO) test -count=1 -v ./test/e2e

.PHONY: setup-e2e
setup-e2e: ## Install opr-paas CRDs into the current cluster (no operator needed).
	$(KUBECTL) apply --server-side -k test/e2e/crd/
	$(KUBECTL) wait --for=condition=Established crd/paasconfig.cpet.belastingdienst.nl --timeout=60s
	$(KUBECTL) wait --for=condition=Established crd/paas.cpet.belastingdienst.nl --timeout=60s
	$(KUBECTL) wait --for=condition=Established crd/paasns.cpet.belastingdienst.nl --timeout=60s

.PHONY: kind-create-cluster
kind-create-cluster: kind ## Create a fresh kind cluster for local e2e.
	$(KIND) create cluster

.PHONY: kind-delete-cluster
kind-delete-cluster: kind ## Delete the kind cluster (ignores errors if no cluster exists).
	$(KIND) delete cluster || true

.PHONY: local-e2e
local-e2e: kind-delete-cluster kind-create-cluster setup-e2e test-e2e ## Spin up a kind cluster, install CRDs, build, and run e2e tests.

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
GOTEST_COVERAGE = $(LOCALBIN)/go-test-coverage
KIND = $(LOCALBIN)/kind

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.15.0
GOTEST_COVERAGE_VERSION ?= latest
KIND_VERSION ?= v0.30.0

## Install golangci-lint using official script instead of 'go install' as that
## last one does not yield a working version.
.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	@[ -f "$(GOLANGCI_LINT)-$(GOLANGCI_LINT_VERSION)" ] || { \
		set -e; \
		echo "Downloading golangci-lint $(GOLANGCI_LINT_VERSION)" ;\
		rm -f $(GOLANGCI_LINT) || true ;\
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/refs/tags/$(GOLANGCI_LINT_VERSION)/install.sh | sh -s -- -b $(LOCALBIN) $(GOLANGCI_LINT_VERSION) ;\
		mv $(GOLANGCI_LINT) $(GOLANGCI_LINT)-$(GOLANGCI_LINT_VERSION) ;\
	}
	@ln -sf $(GOLANGCI_LINT)-$(GOLANGCI_LINT_VERSION) $(GOLANGCI_LINT)

.PHONY: gotest-coverage
gotest-coverage: $(GOTEST_COVERAGE) ## Download go-test-coverage locally if necessary.
$(GOTEST_COVERAGE): $(LOCALBIN)
	$(call go-install-tool,$(GOTEST_COVERAGE),github.com/vladopajic/go-test-coverage/v2,$(GOTEST_COVERAGE_VERSION))

.PHONY: kind
kind: $(KIND) ## Download kind locally if necessary.
$(KIND): $(LOCALBIN)
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) $(GO) install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

.PHONY: install-go-test-coverage
install-go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: check-coverage
check-coverage: install-go-test-coverage test ## check unittest coverage
	${GOBIN}/go-test-coverage --config=./.testcoverage.yaml
