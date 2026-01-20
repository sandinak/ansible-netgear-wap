.PHONY: help venv discovery clean test

PYTHON := python3
VENV := venv
VENV_BIN := $(VENV)/bin
PIP := $(VENV_BIN)/pip
PYTHON_VENV := $(VENV_BIN)/python

# Default target
help:
	@echo "NETGEAR WAX210 Ansible Collection"
	@echo ""
	@echo "Available targets:"
	@echo "  venv       - Create Python virtual environment"
	@echo "  discovery  - Set up environment for LuCI interface discovery"
	@echo "  clean      - Remove virtual environment and cache files"
	@echo "  test       - Run Ansible module tests"
	@echo ""
	@echo "Modules:"
	@echo "  netgear_wax210_info     - Read AP configuration (read-only)"
	@echo "  netgear_wax210_wireless - Configure SSIDs (VLAN, passphrase, radios)"
	@echo "  netgear_wax210_radio    - Configure radio channels"
	@echo "  netgear_wax210_system   - Configure AP name, management interface"

# Create virtual environment
venv:
	@echo "Creating Python virtual environment..."
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	@echo "✅ Virtual environment created at $(VENV)/"

# Discovery environment setup
discovery: venv
	@echo ""
	@echo "=========================================="
	@echo "Setting up LuCI Discovery Environment"
	@echo "=========================================="
	@echo ""
	@echo "Installing discovery dependencies..."
	$(PIP) install selenium mitmproxy
	@echo ""
	@echo "Checking for geckodriver (Firefox WebDriver)..."
	@if command -v geckodriver >/dev/null 2>&1; then \
		echo "✅ geckodriver found: $$(which geckodriver)"; \
	else \
		echo "❌ geckodriver not found"; \
		echo ""; \
		echo "Install with:"; \
		echo "  macOS:   brew install geckodriver"; \
		echo "  Linux:   Download from https://github.com/mozilla/geckodriver/releases"; \
		echo ""; \
		exit 1; \
	fi
	@echo ""
	@echo "Checking for Firefox..."
	@if command -v firefox >/dev/null 2>&1 || [ -d "/Applications/Firefox.app" ]; then \
		echo "✅ Firefox found"; \
	else \
		echo "⚠️  Firefox not found - install Firefox browser"; \
	fi
	@echo ""
	@echo "=========================================="
	@echo "✅ Discovery environment ready!"
	@echo "=========================================="
	@echo ""
	@echo "Run analysis with:"
	@echo "  $(PYTHON_VENV) automated_luci_analyzer.py --host <host> --password <pass>"
	@echo ""

# Clean up
clean:
	@echo "Cleaning up..."
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf library/__pycache__
	rm -rf plugins/__pycache__
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "✅ Cleaned up"

# Test Ansible modules
test: venv
	@echo "Running Ansible module tests..."
	$(PIP) install ansible
	ansible-playbook test_wireless_config.yml
	@echo "✅ Tests complete"

