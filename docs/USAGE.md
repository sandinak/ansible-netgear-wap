# NETGEAR WAX210 Ansible Collection - Usage Guide

## Overview

This Ansible collection provides modules for managing NETGEAR WAX210 wireless access points.

## Modules

| Module | Purpose |
|--------|---------|
| `netgear_wax210_info` | Read-only information gathering |
| `netgear_wax210_wireless` | SSID configuration (VLAN, passphrase, radios) |
| `netgear_wax210_radio` | Radio channel configuration |
| `netgear_wax210_system` | AP name, management interface settings |

## Quick Start

### 1. Read AP Configuration

```yaml
- name: Get all SSIDs from AP
  netgear_wax210_info:
    host: 172.19.4.10
    password: "{{ wap_password }}"
  register: ap_info

- debug:
    msg: "Found {{ ap_info.ssids | length }} SSIDs"
```

### 2. Configure SSID VLAN

```yaml
- name: Set VOV SSID to VLAN 121
  netgear_wax210_wireless:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    ssid_name: "VOV"
    vlan: "vlan121"
    state: enabled
```

### 3. Configure Radio Channels

```yaml
- name: Set channels to auto
  netgear_wax210_radio:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    wifi0_channel: "auto"  # 2.4GHz
    wifi1_channel: "auto"  # 5GHz
```

### 4. Configure AP Name

```yaml
- name: Set AP name
  netgear_wax210_system:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    ap_name: "LOBBY-WAP"
```

### 5. Disable Management Interface

```yaml
- name: Disable 2.4GHz management interface
  netgear_wax210_system:
    host: 172.19.4.10
    password: "{{ wap_password }}"
    mgmt_interface_2g: false
```

## Module Parameters

### Common Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `host` | Yes | - | IP address of the WAX210 |
| `password` | Yes | - | Admin password |
| `username` | No | admin | Admin username |
| `validate_certs` | No | false | Validate SSL certificates |

### netgear_wax210_wireless

| Parameter | Description |
|-----------|-------------|
| `ssid_name` | Name of the SSID to configure |
| `vlan` | VLAN name (e.g., "vlan121") |
| `passphrase` | WiFi password |
| `encryption` | Encryption type (psk2, sae-mixed, etc.) |
| `wifi0_enabled` | Enable on 2.4GHz radio |
| `wifi1_enabled` | Enable on 5GHz radio |
| `state` | present, enabled, disabled |

### netgear_wax210_radio

| Parameter | Description |
|-----------|-------------|
| `wifi0_channel` | 2.4GHz channel (auto, 1-11) |
| `wifi1_channel` | 5GHz channel (auto, 36-165) |

### netgear_wax210_system

| Parameter | Description |
|-----------|-------------|
| `ap_name` | Access point name (max 15 chars) |
| `mgmt_interface_2g` | Enable/disable 2.4GHz management interface |
| `mgmt_interface_5g` | Enable/disable 5GHz management interface |

## Check Mode

All modules support Ansible check mode (`--check`) to preview changes without applying them:

```bash
ansible-playbook configure_aps.yml --check
```

## Idempotency

All modules are idempotent - running them multiple times with the same parameters will only make changes if the current state differs from the desired state.

