FIND := find
RM := rm -rf

TOP_DIR := .
SRC_DIR := $(TOP_DIR)/ff3_cryptography
TEST_DIR := $(TOP_DIR)/tests

BLACK := black --line-length 88
ISORT := isort --profile black --line-length 88

test: clean
	@pip install -r requirements-dev.txt
	@export PYTHONPATH=$$(pwd)/ff3_cryptography && echo $$PYTHONPATH
	@export PYTHONPATH=$$(pwd)/ff3_cryptography && pytest -s -v --cov-report term --cov=./ff3_cryptography ./tests

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
	@echo "Finished cleaning up distribution artifacts."

.PHONY: build pytest upload test

