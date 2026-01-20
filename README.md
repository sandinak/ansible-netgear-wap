# NETGEAR WAX210 Ansible Collection

Ansible modules for managing NETGEAR WAX210 wireless access points.

## Features

| Feature | Module | Status |
|---------|--------|--------|
| Read SSID configuration | `netgear_wax210_info` | ✅ |
| Configure SSID (VLAN, passphrase, radios) | `netgear_wax210_wireless` | ✅ |
| Configure radio channels | `netgear_wax210_radio` | ✅ |
| Configure AP name | `netgear_wax210_system` | ✅ |
| Enable/disable management interface | `netgear_wax210_system` | ✅ |

## Quick Start

```yaml
# Read all SSIDs
- name: Get AP configuration
  netgear_wax210_info:
    host: 172.19.4.10
    password: "{{ wap_password }}"
  register: ap_config

# Configure SSID VLAN
- name: Set VOV to VLAN 121
  netgear_wax210_wireless:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    ssid_name: "VOV"
    vlan: "vlan121"
    state: enabled

# Set channels to auto
- name: Configure radio channels
  netgear_wax210_radio:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    wifi0_channel: "auto"
    wifi1_channel: "auto"

# Set AP name
- name: Configure AP name
  netgear_wax210_system:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    ap_name: "LOBBY-WAP"
```

## Installation

```bash
git clone <repository-url>
cd ansible-netgear-wap
```

Modules are in `library/` and auto-discovered by Ansible.

## Documentation

- [Usage Guide](docs/USAGE.md) - Detailed module usage and examples
- [Extending Guide](docs/EXTENDING.md) - How to analyze new WAX models
- [WAX210 Reference](docs/models/WAX210.md) - Technical details for AI/developers

## Analyzing New Models

Use the automated analyzer to discover API endpoints for new WAX models:

```bash
make discovery  # Install dependencies
python3 automated_luci_analyzer.py --host <IP> --password <pass>
```

## Requirements

- Python 3.6+
- Ansible 2.9+
- For analyzer: Firefox, geckodriver, selenium, mitmproxy

## Tested Firmware

- WAX210 V1.1.0.34

## License

GNU General Public License v3.0+

