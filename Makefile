# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

TOOLS_DIR := tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
GOBIN := $(shell go env GOBIN)

GOLANGCI_LINT := $(TOOLS_BIN_DIR)/golangci-lint
$(GOLANGCI_LINT): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); GOBIN=$(TOOLS_BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint

check-linter: ## Install and run golang linter
check-linter: | $(GOLANGCI_LINT)
	# Run golangci-lint linter
	$(GOLANGCI_LINT) run -c golangci.yml

fix-linter: ## Install and run golang linter, with fixes
fix-linter: | $(GOLANGCI_LINT)
	# Run golangci-lint linter
	$(GOLANGCI_LINT) run -c golangci.yml --fix
