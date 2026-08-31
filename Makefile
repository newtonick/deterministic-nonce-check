# Determinism harness: verify the JS signer agrees with embit byte-for-byte.
#
# The JS side generates cases with the site's own modules; the Python side signs
# them with real embit, the library SeedSigner and Krux are built on.

VENV    := .venv
PY      := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
PYTEST  := $(VENV)/bin/pytest
COUNT   ?= 100
SEED    ?= make-$(shell date +%s)

.PHONY: test cases pytest venv clean-cases clean

## Full run: build the venv if needed, generate cases, check them against embit.
test: venv cases pytest

venv: $(VENV)/.installed

$(VENV)/.installed: embit-test-harness/requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r embit-test-harness/requirements.txt
	@touch $@

## Generate COUNT stratified cases signed by the JS implementation.
cases:
	npx tsx embit-test-harness/generate_cases.mts --count $(COUNT) --seed "$(SEED)"

## Compare every generated case against embit.
pytest:
	$(PYTEST) embit-test-harness -q

clean-cases:
	rm -rf embit-test-harness/cases

clean: clean-cases
	rm -rf $(VENV) node_modules dist
