# NETGEAR WAX Series Ansible Collection

Ansible modules for managing NETGEAR WAX series wireless access points with automatic model detection.

## Supported Models

| Model  | Status | Notes |
|--------|--------|-------|
| WAX210 | ✅ | Fully tested |
| WAX218 | ✅ | Fully tested |

## Features

| Feature | Module | Status |
|---------|--------|--------|
| Read SSID configuration | `netgear_wax_info` | ✅ |
| Configure SSID (VLAN, passphrase, radios) | `netgear_wax_wireless` | ✅ |
| Configure radio channels | `netgear_wax_radio` | ✅ |
| Configure AP name | `netgear_wax_system` | ✅ |
| Enable/disable management interface | `netgear_wax_system` | ✅ |

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
git clone <repository-url>
cd ansible-netgear-wap
```

Modules are in `plugins/modules/` as an Ansible Galaxy collection.

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

- WAX210 V1.1.0.34
- WAX218 (tested)

## License

GNU General Public License v3.0+

