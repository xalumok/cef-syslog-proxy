.DEFAULT_GOAL := help
VENV := .venv
PY := $(VENV)/bin/python
VECTOR_VERSION := 0.51.0

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Create the venv and install everything
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -e ".[dev]"
	cd ui && npm install

.PHONY: vector
vector: ## Download the pinned Vector binary into .tools/
	@mkdir -p .tools
	@case "$$(uname -s)-$$(uname -m)" in \
	  Darwin-arm64) T=arm64-apple-darwin ;; \
	  Darwin-x86_64) T=x86_64-apple-darwin ;; \
	  Linux-x86_64) T=x86_64-unknown-linux-gnu ;; \
	  Linux-aarch64) T=aarch64-unknown-linux-gnu ;; \
	  *) echo "unsupported platform"; exit 1 ;; \
	esac; \
	curl -sSfL "https://packages.timber.io/vector/$(VECTOR_VERSION)/vector-$(VECTOR_VERSION)-$$T.tar.gz" \
	  | tar xz -C .tools ; \
	find .tools -type f -name vector -perm -u+x -exec mv {} .tools/vector \; ; \
	find .tools -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
	@echo "Vector installed at .tools/vector. Add it to PATH:"
	@echo "  export PATH=\"$$PWD/.tools:\$$PATH\""

.PHONY: lint
lint: ## Lint and format check
	$(VENV)/bin/ruff check src tests
	$(VENV)/bin/ruff format --check src tests

.PHONY: fix
fix: ## Auto-fix lint and formatting
	$(VENV)/bin/ruff check src tests --fix
	$(VENV)/bin/ruff format src tests

.PHONY: types
types: ## Type check, with --strict on the compiler
	$(VENV)/bin/mypy src/sixthsense
	$(VENV)/bin/mypy --strict src/sixthsense/compiler

.PHONY: test
test: ## Unit and property tests (no Vector needed)
	$(PY) -m pytest tests -q --ignore=tests/test_dataplane_e2e.py

.PHONY: e2e
e2e: ## End-to-end tests against real Vector
	$(PY) -m pytest tests/test_dataplane_e2e.py -q

.PHONY: perf
perf: ## Measure throughput and added latency against the D-21 targets
	$(VENV)/bin/ssperf --rate 20000 --seconds 10

.PHONY: perf-burst
perf-burst: ## Measure the burst target (send as fast as the machine allows)
	$(VENV)/bin/ssperf --rate 0 --count 300000

.PHONY: perf-scale
perf-scale: ## Sweep Vector thread counts to size a deployment
	$(VENV)/bin/ssperf --scale 1,2,4,8 --rate 20000 --seconds 6

.PHONY: perf-workers
perf-workers: ## Sweep Vector process counts; this is the one that scales
	$(VENV)/bin/ssperf --workers-sweep 1,2,4 --rate 25000 --seconds 6

.PHONY: perf-rules
perf-rules: ## Sweep rule-chain length to find where evaluation stops being free
	$(VENV)/bin/ssperf --rules-sweep 1,10,50,100,200 --rate 20000 --seconds 5

.PHONY: security
security: ## SAST and dependency scanning
	$(VENV)/bin/bandit -r src/sixthsense -ll
# Audit the declared dependencies rather than the environment. Auditing the environment fails
# under --strict, because sixthsense itself is installed editable and cannot be looked up on
# PyPI. Dropping --strict would have hidden that as a warning, along with any real package
# that failed to resolve.
	$(VENV)/bin/pip-audit --strict .

.PHONY: check
check: lint types test ## Everything CI runs, except the data plane suite

.PHONY: ui
ui: ## Build the React app into ui/dist
	cd ui && npm run build

.PHONY: dev
dev: ## Run the control plane with reload
	$(VENV)/bin/ssctl serve --reload

.PHONY: try
try: ## Run the whole stack locally and send traffic through it
	./scripts/demo.sh

.PHONY: demo
demo: ## Seed a database with example rules and a user
	rm -f demo.db
	SS_DATABASE_URL="sqlite+pysqlite:///./demo.db" $(VENV)/bin/ssctl init-db
	SS_DATABASE_URL="sqlite+pysqlite:///./demo.db" $(VENV)/bin/ssctl adduser analyst --role rule-editor --password demo1234
	@echo "Run: SS_DATABASE_URL='sqlite+pysqlite:///./demo.db' make dev"

.PHONY: compile
compile: ## Print the Vector config the current chain produces
	$(VENV)/bin/ssctl compile

.PHONY: clean
clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache ui/dist demo.db
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
