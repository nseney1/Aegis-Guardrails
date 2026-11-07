# Aegis Guardrails: developer entry points (install, test, lint, build).
# Override the interpreter with `make test PYTHON=/path/to/python`.

PYTHON ?= python3

.PHONY: install test lint build

install: ## Editable install with the dev tools
	$(PYTHON) -m pip install -e ".[dev]"

# HOME points at a throwaway directory so no test can read or write the real
# ~/.aegis, ~/.claude, ~/.gemini or ~/.codex. PYTHONUSERBASE is resolved first,
# so packages installed with `pip install --user` stay importable. The HOME is
# made in /tmp, never under $TMPDIR: a TMPDIR inside the real home would put the
# isolated HOME there too, and discovery would walk up into the real ~/.aegis.
test: ## Run the full suite with an isolated HOME
	@userbase="$${PYTHONUSERBASE:-$$($(PYTHON) -m site --user-base)}"; \
	home="$$(mktemp -d /tmp/aegis-test-home.XXXXXX)"; trap 'rm -rf "$$home"' EXIT; \
	xdist=""; if $(PYTHON) -c "import xdist" >/dev/null 2>&1; then xdist="-n auto"; fi; \
	HOME="$$home" USERPROFILE="$$home" XDG_CONFIG_HOME="$$home/.config" PYTHONUSERBASE="$$userbase" \
	  $(PYTHON) -m pytest tests -q $$xdist

lint: ## Syntax errors and undefined names (ruff, ignoring user-level config)
	$(PYTHON) -m ruff check --isolated --select E9,F63,F7,F82 aegis_cli aegis_core aegis_mcp aegis_sdk tests .github/scripts tools

build: ## Build the wheel and sdist into dist/
	$(PYTHON) -m build
