MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))
BIN_DIR := $(ROOT_DIR)/bin

build:
	@echo "Building Grimoire..."
	@mkdir -p "$(BIN_DIR)"
	@go build -o $(BIN_DIR)/grimoire cmd/grimoire/*.go
	@echo "Build completed. Binaries are saved in $(BIN_DIR)"

test:
	@echo "Running unit tests..."
	@go test ./... -v

thirdparty-licenses:
	@echo "Retrieving third-party licenses..."
	@go install github.com/google/go-licenses@latest
	@$(GOPATH)/bin/go-licenses csv github.com/datadog/grimoire/cmd/grimoire | sort > $(ROOT_DIR)/LICENSE-3rdparty.csv
	@echo "Third-party licenses retrieved and saved to $(ROOT_DIR)/LICENSE-3rdparty.csv"

mocks:
mocks:
	@echo "Generating mocks..."
	@mockery --dir $(GOPATH)/src/github.com/DataDog/stratus-red-team/v2/pkg/stratus/runner --name Runner --output=pkg/grimoire/detonators/mocks --structname StratusRedTeamRunner --filename StratusRedTeamRunner.go
	@echo "Mocks generated successfully."