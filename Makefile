PY ?= python3
.PHONY: setup test lint types demo eval-dev eval check
setup:
	$(PY) -m venv .venv && . .venv/bin/activate && pip install -e '.[test,interop,dev]'
test:
	pytest -q
lint:
	ruff check src tests && ruff format --check src tests
types:
	mypy
check: lint types test
demo:
	$(PY) -m weir_eval.demo
