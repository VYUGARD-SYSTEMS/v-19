.PHONY: build install test lint clean

# ── Build ──────────────────────────────────────────────────────
build:
	python -m build

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# ── Test ───────────────────────────────────────────────────────
test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ --cov=pkg --cov=cli --cov=internal --cov-report=term-missing

# ── Lint ───────────────────────────────────────────────────────
lint:
	python -m py_compile cli/v19/main.py
	python -m py_compile pkg/engine/scanner.py
	python -m py_compile pkg/engine/bridges.py

# ── Clean ──────────────────────────────────────────────────────
clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ── Run ────────────────────────────────────────────────────────
analyze:
	v-19 analyze

version:
	v-19 --version
