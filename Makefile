.PHONY: help venv analyze analyze-clean clean test

PYTHON := python3
VENV := venv
VENV_BIN := $(VENV)/bin
PIP := $(VENV_BIN)/pip
PYTHON_VENV := $(VENV_BIN)/python
ANALYZER_DIR := tools/analyzer

# Default target
help:
	@echo "NETGEAR WAX Series Ansible Collection"
	@echo ""
	@echo "Available targets:"
	@echo "  venv           - Create Python virtual environment"
	@echo "  analyze        - Analyze a WAX AP to discover endpoints and forms"
	@echo "  analyze-clean  - Clean analyzer output files (keeps tools)"
	@echo "  clean          - Remove virtual environment and cache files"
	@echo "  test           - Run Ansible module syntax check"
	@echo ""
	@echo "Modules (support WAX210, WAX218 with auto-detection):"
	@echo "  netgear_wax210_info      - Read AP configuration (read-only)"
	@echo "  netgear_wax210_wireless  - Configure SSIDs (VLAN, passphrase, radios)"
	@echo "  netgear_wax210_radio     - Configure radio channels"
	@echo "  netgear_wax210_system    - Configure AP name, management interface"
	@echo ""
	@echo "Analyze usage:"
	@echo "  make analyze HOST=172.19.4.10 PASSWORD=mypassword"

# Create virtual environment with base dependencies
venv:
	@echo "Creating Python virtual environment..."
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install requests pycryptodome
	@echo "✅ Virtual environment created at $(VENV)/"

# Analyze a WAX AP - discovers endpoints and forms using Selenium
analyze: venv
ifndef HOST
	$(error HOST is required. Usage: make analyze HOST=172.19.4.10 PASSWORD=mypassword)
endif
ifndef PASSWORD
	$(error PASSWORD is required. Usage: make analyze HOST=172.19.4.10 PASSWORD=mypassword)
endif
	@echo ""
	@echo "=========================================="
	@echo "Setting up analysis environment"
	@echo "=========================================="
	$(PIP) install --quiet selenium mitmproxy
	@echo "Checking for geckodriver..."
	@if command -v geckodriver >/dev/null 2>&1; then \
		echo "✅ geckodriver found"; \
	else \
		echo "❌ geckodriver not found"; \
		echo "Install with: brew install geckodriver (macOS)"; \
		exit 1; \
	fi
	@echo "Checking for Firefox..."
	@if command -v firefox >/dev/null 2>&1 || [ -d "/Applications/Firefox.app" ]; then \
		echo "✅ Firefox found"; \
	else \
		echo "❌ Firefox not found - please install Firefox"; \
		exit 1; \
	fi
	@echo ""
	@echo "=========================================="
	@echo "Analyzing WAX AP at $(HOST)"
	@echo "=========================================="
	cd $(ANALYZER_DIR) && ../../$(PYTHON_VENV) automated_luci_analyzer.py --host $(HOST) --password "$(PASSWORD)"

# Clean analyzer output files (keeps tools)
analyze-clean:
	@echo "Cleaning analyzer output files..."
	rm -f $(ANALYZER_DIR)/*.html $(ANALYZER_DIR)/*.png $(ANALYZER_DIR)/*.json $(ANALYZER_DIR)/*.txt
	rm -rf $(ANALYZER_DIR)/luci_capture_*
	@echo "✅ Analyzer output cleaned"

# Clean up
clean:
	@echo "Cleaning up..."
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf plugins/__pycache__
	rm -rf analysis_*
	rm -rf luci_session_*
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "✅ Cleaned up"

# Test Ansible modules - syntax check
test: venv
	@echo "Running module syntax check..."
	$(PIP) install --quiet ansible requests
	@for f in plugins/modules/*.py; do \
		echo "Checking $$f..."; \
		$(PYTHON_VENV) -m py_compile $$f || exit 1; \
	done
	@echo "✅ All modules compile successfully"

# Integration test - requires access to WAX devices
test-integration: venv
	@echo "Running integration tests on WAX210 and WAX218..."
	$(PIP) install --quiet requests
	$(PYTHON_VENV) tests/test_all_modules.py

