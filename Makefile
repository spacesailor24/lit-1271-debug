# Makefile for deploying WhitelistEIP1271 contract

# Load environment variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Configuration
SCRIPT_PATH = script/SimpleEIP1271.s.sol:DeploySimpleEIP1271

# Default target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  deploy    - Deploy the WhitelistEIP1271 contract to Yellowstone"
	@echo "  build     - Build the contracts"
	@echo "  test      - Run tests"
	@echo "  clean     - Clean build artifacts"

# Build contracts
.PHONY: build
build:
	forge build

# Run tests
.PHONY: test
test:
	forge test

# Deploy to Yellowstone RPC
.PHONY: deploy
deploy: build
	@echo "Deploying to Yellowstone RPC: $(FORGE_DEPLOYMENT_RPC_URL)"
	forge script $(SCRIPT_PATH) \
		--rpc-url $(FORGE_DEPLOYMENT_RPC_URL) \
		--broadcast

# Clean build artifacts
.PHONY: clean
clean:
	forge clean