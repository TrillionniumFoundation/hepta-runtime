# Hepta Runtime development tasks
.PHONY: help coverage

help: ## List available tasks
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

# Coverage requires cargo-llvm-cov, cargo-nextest 0.9.137 and Rust 1.95.0
# with llvm-tools-preview. Preserve CI's process isolation and zero retries.
# Test-only files are excluded so percentages describe product code.
coverage: ## Generate test coverage report (cargo-llvm-cov)
	@echo "Generating coverage report..."
	umask 022; cargo +1.95.0 llvm-cov nextest --locked --all-targets --all-features \
		--test-threads 1 --retries 0 --no-fail-fast --ignore-filename-regex '_tests\.rs$$'
