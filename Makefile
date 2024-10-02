FIND := find
RM := rm -rf

TOP_DIR := .
SRC_DIR := $(TOP_DIR)/ff3_cryptography
TEST_DIR := $(TOP_DIR)/tests
DIST_DIR := $(TOP_DIR)/dist

BLACK := black --line-length 88
ISORT := isort --profile black --line-length 88
PYTHON := python
PIP_INSTALL := $(PYTHON) -m pip install
BDIST := $(PYTHON) setup.py bdist_wheel sdist
PUBLISH := twine upload

build: clean
	@echo "Building..."
	@$(PIP_INSTALL) wheel
	@$(BDIST)
	@echo "Finished building..."


upload:
	@echo "Uploading to PyPI..."
	@$(PUBLISH) dist/*
	@echo "Finished uploading to PyPI..."


test-deps:
	@pip install -r requirements-dev.txt

test: clean test-deps
	@pytest -s -v --cov-report term --cov=./ff3_cryptography ./tests

fmt:
	@echo "Formatting code..."
	@$(ISORT) $(SRC_DIR) $(TEST_DIR)
	@$(BLACK) $(SRC_DIR) $(TEST_DIR)
	@echo "Finished formatting code."

clean:
	@echo "Cleaning up distribution artifacts..."
	@$(RM) $(DIST_DIR)
	@$(RM) $(SRC_DIR)/*.egg-info
	@$(RM) $(TOP_DIR)/.mypy_cache
	@$(FIND) $(SRC_DIR) $(TEST_DIR) $(SCRIPTS_DIR) \( -name __pycache__ -a -type d \) -prune -exec rm -rf {} \;
	@echo "Finished cleaning up distribution artifacts."

.PHONY: build pytest upload test test-deps

