FIND := find
RM := rm -rf

test: clean
	@pip install -r requirements-dev.txt
	@export PYTHONPATH=$$(pwd)/ff3_cryptography && echo $$PYTHONPATH
	@export PYTHONPATH=$$(pwd)/ff3_cryptography && pytest -s -v --cov-report term --cov=./ff3_cryptography ./tests


clean:
	@echo "Cleaning up distribution artifacts..."
	@$(RM) $(DIST_DIR)
	@$(RM) $(SRC_DIR)/*.egg-info
	@$(RM) $(TOP_DIR)/.mypy_cache
	@echo "Finished cleaning up distribution artifacts."

.PHONY: build pytest upload test

