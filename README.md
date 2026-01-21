# NETGEAR WAX Series Ansible Collection

Ansible modules for managing NETGEAR WAX series wireless access points with automatic model detection.

## Supported Models

| Model  | Auth | Status | Notes |
|--------|------|--------|-------|
| WAX210 | SHA-512 | ✅ Fully tested | stok in URL |
| WAX218 | MD5 | ✅ Fully tested | stok in body |

Additional models using the same LuCI interface should work automatically.

## Features

| Feature | Module | Status |
|---------|--------|--------|
| Read SSID configuration | `netgear_wax_info` | ✅ |
| Configure SSID (VLAN, passphrase, radios) | `netgear_wax_wireless` | ✅ |
| Configure radio channels | `netgear_wax_radio` | ✅ |
| Configure AP name | `netgear_wax_system` | ✅ |
| Enable/disable management interface | `netgear_wax_system` | ✅ |

## Multi-Model Support

All modules automatically detect:
- **Authentication type**: SHA-512 (newer firmware) or MD5 (older firmware)
- **Session token location**: URL redirect (WAX210) or page body (WAX218)
- **SSID popup endpoint**: Model-specific popup forms

## Quick Start

```yaml
# Read all SSIDs (works on any supported model)
- name: Get AP configuration
  netgear_wax_info:
    host: 172.19.4.10
    password: "{{ wap_password }}"
  register: ap_config

# Configure SSID VLAN
- name: Set VOV to VLAN 121
  netgear_wax_wireless:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    ssid_name: "VOV"
    vlan: "vlan121"
    state: enabled

# Optional: Override model detection
- name: Force WAX218 model
  netgear_wax_wireless:
    host: 172.19.4.14
    password: "{{ wap_password }}"
    model: WAX218  # Optional - auto-detected if omitted
    ssid_name: "VOV"
    vlan: "vlan121"
```

## Installation

```bash
# From GitHub
ansible-galaxy collection install git+https://github.com/sandinak/ansible-netgear-wap.git

# Specific version
ansible-galaxy collection install git+https://github.com/sandinak/ansible-netgear-wap.git,v1.1.2
```

Or clone for development:
```bash
git clone https://github.com/sandinak/ansible-netgear-wap.git
cd ansible-netgear-wap
```

## Documentation

- [Usage Guide](docs/USAGE.md) - Detailed module usage and examples
- [Extending Guide](docs/EXTENDING.md) - How to analyze new WAX models
- [WAX210 Reference](docs/models/WAX210.md) - Technical details for AI/developers

## Analyzing New Models

Use the automated analyzer to discover API endpoints for new WAX models:

```bash
make analyze HOST=<IP> PASSWORD=<pass>
```

Analysis tools are in `tools/analyzer/`.

## Requirements

- Python 3.6+
- Ansible 2.9+
- For analyzer: Firefox, geckodriver (installed via `make analyze`)

## Tested Firmware

| Model | Firmware | Auth | stok Location |
|-------|----------|------|---------------|
| WAX210 | V1.1.0.34 | SHA-512 | URL |
| WAX218 | V1.x | MD5 | Body |

## Running Tests

```bash
# Set password and run integration tests
export WAX_PASSWORD='your_password'
python3 tests/test_all_modules.py

# Or via make
make test-integration
```

## Changelog

### v1.1.3
- Refactored all modules to use central `module_utils/wax_api.py` base class
- Eliminated duplicate login, CSRF, HTTP, and model detection code across modules
- Fixed wireless module CSRF handling in popup form submissions
- Fixed VLAN regex to handle "vlanXXX" format stored by devices
- Added selective test execution flags to replication tests
- All 12/12 tests pass on WAX210 and WAX218

### v1.1.2
- Fixed HTTP 403 errors when changing system settings
- Fixed device lockouts after AP name configuration
- Added proper CSRF token handling with ajax_setCsrf call
- All write modules now use consistent CSRF paradigm
- All 12 tests pass on WAX210 and WAX218

### v1.1.1
- Fixed stok extraction for multi-model support (URL and body)
- Fixed info module to use generic interface endpoint
- All 12 tests pass on WAX210 and WAX218

### v1.1.0
- Renamed modules from `netgear_wax210_*` to `netgear_wax_*`
- Added automatic model detection (SHA-512 vs MD5 auth)
- Added WAX218 support with model-specific endpoints

## License

GNU General Public License v3.0+

