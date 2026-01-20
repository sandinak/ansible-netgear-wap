#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Ansible Netgear WAP Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: netgear_wax_wireless
short_description: Manage Netgear WAX series wireless access point configuration
version_added: "1.0.0"
description:
    - Manage wireless SSID configuration on Netgear WAX series access points
    - Supports WAX210 and WAX218 models with automatic model detection
    - Configure SSID, encryption, VLAN, isolation, and other wireless settings
    - Supports both 2.4GHz and 5GHz radios
options:
    host:
        description: IP address or hostname of the access point
        required: true
        type: str
    username:
        description: Username for authentication
        required: false
        type: str
        default: admin
    password:
        description: Password for authentication
        required: true
        type: str
        no_log: true
    ssid_name:
        description: Name of the SSID to configure
        required: true
        type: str
    state:
        description: Whether the SSID should be present or absent
        required: false
        type: str
        choices: ['present', 'absent', 'enabled', 'disabled']
        default: present
    radio:
        description: Which radio to configure (2.4GHz, 5GHz, or both)
        required: false
        type: str
        choices: ['2.4ghz', '5ghz', 'both']
        default: both
    encryption:
        description: Encryption type for the SSID
        required: false
        type: str
        choices: ['none', 'psk2', 'psk2+ccmp', 'sae-mixed', 'sae-mixed+ccmp']
    passphrase:
        description: WiFi passphrase/password
        required: false
        type: str
        no_log: true
    vlan:
        description: VLAN ID or network name for the SSID
        required: false
        type: str
    isolation:
        description: Enable client isolation
        required: false
        type: bool
    hidden:
        description: Hide SSID from broadcast
        required: false
        type: bool
    band_steering:
        description: Enable band steering
        required: false
        type: bool
    validate_certs:
        description: Validate SSL certificates
        required: false
        type: bool
        default: false
    model:
        description:
            - Override automatic model detection
            - If not specified, the module auto-detects from the login page
        required: false
        type: str
        choices: ['WAX210', 'WAX218']
        default: null
author:
    - Ansible Netgear WAP Project
'''

EXAMPLES = r'''
# Configure a new SSID with WPA3 encryption
- name: Configure VOV SSID
  netgear_wax210_wireless:
    host: 172.19.4.10
    password: your_password_here
    ssid_name: VOV
    encryption: sae-mixed+ccmp
    passphrase: MySecurePassword
    vlan: vlan121
    isolation: true
    state: enabled

# Read configuration from one AP
- name: Get wireless config
  netgear_wax210_wireless:
    host: 172.19.4.10
    password: your_password_here
    ssid_name: VOV
    state: present
  register: wap_config

# Disable an SSID
- name: Disable SSID
  netgear_wax210_wireless:
    host: 172.19.4.11
    password: your_password_here
    ssid_name: TestSSID
    state: disabled
'''

RETURN = r'''
changed:
    description: Whether the configuration was changed
    type: bool
    returned: always
config:
    description: Current SSID configuration
    type: dict
    returned: always
message:
    description: Status message
    type: str
    returned: always
'''

import json
import hashlib
import re
import ssl
import http.cookiejar
import urllib.request as urllib_request
import urllib.error as urllib_error
from urllib.parse import urljoin, urlencode

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes

# AES encryption for passphrases
# NETGEAR WAX210 uses AES-256-ECB with PKCS7 padding
AES_KEY = b'HuKylGfhLMj6Fo6D4kBjFAdpqV37UonN'


def aes_encrypt_passphrase(plaintext):
    """Encrypt passphrase using AES-256-ECB with PKCS7 padding.

    Implementation without external dependencies (pycryptodome not available in Ansible).
    Uses pure Python AES implementation for compatibility.
    """
    import base64

    # PKCS7 padding
    block_size = 16
    padding_len = block_size - (len(plaintext) % block_size)
    padded = plaintext.encode('utf-8') + bytes([padding_len] * padding_len)

    # AES-256 key expansion (simplified for ECB mode)
    key = AES_KEY

    # S-box for AES
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]

    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def xtime(a):
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

    def mix_column(col):
        t = col[0] ^ col[1] ^ col[2] ^ col[3]
        u = col[0]
        col[0] ^= t ^ xtime(col[0] ^ col[1])
        col[1] ^= t ^ xtime(col[1] ^ col[2])
        col[2] ^= t ^ xtime(col[2] ^ col[3])
        col[3] ^= t ^ xtime(col[3] ^ u)
        return col

    # Key expansion
    def expand_key(key):
        w = [list(key[i:i+4]) for i in range(0, 32, 4)]
        for i in range(8, 60):
            temp = list(w[i-1])
            if i % 8 == 0:
                temp = temp[1:] + temp[:1]
                temp = [sbox[b] for b in temp]
                temp[0] ^= rcon[i // 8 - 1]
            elif i % 8 == 4:
                temp = [sbox[b] for b in temp]
            w.append([w[i-8][j] ^ temp[j] for j in range(4)])
        return w

    def add_round_key(state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i * 4 + j]

    def sub_bytes(state):
        for i in range(4):
            for j in range(4):
                state[i][j] = sbox[state[i][j]]

    def shift_rows(state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]

    def mix_columns(state):
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            col = mix_column(col)
            for j in range(4):
                state[j][i] = col[j]

    def encrypt_block(block, expanded_key):
        state = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
        add_round_key(state, [b for w in expanded_key[0:4] for b in w])
        for r in range(1, 14):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, [b for w in expanded_key[r*4:(r+1)*4] for b in w])
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, [b for w in expanded_key[56:60] for b in w])
        return bytes([state[i][j] for i in range(4) for j in range(4)])

    expanded_key = expand_key(key)
    ciphertext = b''
    for i in range(0, len(padded), 16):
        ciphertext += encrypt_block(list(padded[i:i+16]), expanded_key)

    return base64.b64encode(ciphertext).decode('utf-8')


def aes_decrypt_passphrase(ciphertext):
    """Decrypt passphrase using AES-256-ECB with PKCS7 padding."""
    import base64

    # Inverse S-box for AES decryption
    inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ]

    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]

    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    key = AES_KEY

    def xtime(a):
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

    def expand_key(key):
        w = [list(key[i:i+4]) for i in range(0, 32, 4)]
        for i in range(8, 60):
            temp = list(w[i-1])
            if i % 8 == 0:
                temp = temp[1:] + temp[:1]
                temp = [sbox[b] for b in temp]
                temp[0] ^= rcon[i // 8 - 1]
            elif i % 8 == 4:
                temp = [sbox[b] for b in temp]
            w.append([w[i-8][j] ^ temp[j] for j in range(4)])
        return w

    def add_round_key(state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i * 4 + j]

    def inv_sub_bytes(state):
        for i in range(4):
            for j in range(4):
                state[i][j] = inv_sbox[state[i][j]]

    def inv_shift_rows(state):
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]

    def inv_mix_column(col):
        u = xtime(xtime(col[0] ^ col[2]))
        v = xtime(xtime(col[1] ^ col[3]))
        col[0] ^= u
        col[1] ^= v
        col[2] ^= u
        col[3] ^= v
        t = col[0] ^ col[1] ^ col[2] ^ col[3]
        uu = col[0]
        col[0] ^= t ^ xtime(col[0] ^ col[1])
        col[1] ^= t ^ xtime(col[1] ^ col[2])
        col[2] ^= t ^ xtime(col[2] ^ col[3])
        col[3] ^= t ^ xtime(col[3] ^ uu)
        return col

    def inv_mix_columns(state):
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            col = inv_mix_column(col)
            for j in range(4):
                state[j][i] = col[j]

    def decrypt_block(block, expanded_key):
        state = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
        add_round_key(state, [b for w in expanded_key[56:60] for b in w])
        for r in range(13, 0, -1):
            inv_shift_rows(state)
            inv_sub_bytes(state)
            add_round_key(state, [b for w in expanded_key[r*4:(r+1)*4] for b in w])
            inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, [b for w in expanded_key[0:4] for b in w])
        return bytes([state[i][j] for i in range(4) for j in range(4)])

    try:
        cipherdata = base64.b64decode(ciphertext)
    except Exception:
        return ''

    expanded_key = expand_key(key)
    plaintext = b''
    for i in range(0, len(cipherdata), 16):
        plaintext += decrypt_block(list(cipherdata[i:i+16]), expanded_key)

    # Remove PKCS7 padding
    if plaintext:
        padding_len = plaintext[-1]
        if padding_len > 0 and padding_len <= 16:
            plaintext = plaintext[:-padding_len]

    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        # If decryption produces invalid UTF-8, return empty string
        return ''


# Encryption type mappings from API values to display names
ENCRYPTION_TYPES = {
    'none': 'None',
    'psk2': 'WPA2-Personal',
    'psk2+ccmp': 'WPA2-Personal',
    'sae': 'WPA3-Personal',
    'sae+ccmp': 'WPA3-Personal',
    'sae-mixed': 'WPA2/WPA3-Personal',
    'sae-mixed+ccmp': 'WPA2/WPA3-Personal',
    'wpa2+ccmp': 'WPA2-Enterprise',
    'wpa3': 'WPA3-Enterprise',
    'wpa3-mixed+ccmp': 'WPA2/WPA3-Enterprise',
}

# Valid encryption choices for the API
VALID_ENCRYPTIONS = ['none', 'psk2', 'sae', 'sae-mixed']

# SSID slot mapping (SSID name to slot number for known SSIDs)
KNOWN_SSID_SLOTS = {
    'SPEAKER': 1,
    'JTW': 2,
    'VOV': 3,
}

# Complete form field template for SSID popup
# Based on captured data from wifi_Encryption_P2P popup
POPUP_FORM_FIELDS = {
    'form_submit': '1',
    'val_csrf': '',  # Required - must be populated
    'fromEncr': '',  # e.g., 'wifi0.network3'
    'opmode': 'ap',
    'device': '',
    'displayMode': '',
    'is_wifi_join': '',
    'vlan_isolation_enable': '1',
}


class WAX210API:
    def __init__(self, module):
        self.module = module
        self.host = module.params['host']
        self.username = module.params.get('username', 'admin')
        self.password = module.params['password']
        self.base_url = f"https://{self.host}"
        self.stok = None
        self.validate_certs = module.params.get('validate_certs', False)

        # Model detection - can be overridden by module param
        self.model = module.params.get('model', None)  # Auto-detect if None
        self.ssid_popup_endpoint = None  # Set during login based on model

        # Create SSL context that doesn't verify certificates
        self.ssl_ctx = ssl.create_default_context()
        if not self.validate_certs:
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

        # Create cookie jar and opener
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib_request.build_opener(
            urllib_request.HTTPCookieProcessor(self.cookie_jar),
            urllib_request.HTTPSHandler(context=self.ssl_ctx)
        )

    def _hash_password_md5(self, password):
        """Hash password with MD5 (old firmware)"""
        return hashlib.md5(to_bytes(password + "\n")).hexdigest()

    def _hash_password_sha512(self, password):
        """Hash password with SHA-512 (new firmware 1.1.0.34+)"""
        return hashlib.sha512(to_bytes(password + "\n")).hexdigest()

    def _make_request(self, url, method='GET', data=None, headers=None):
        """Make HTTP request to the device using urllib"""
        if headers is None:
            headers = {}

        headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0'

        if data and isinstance(data, str):
            data = to_bytes(data)

        req = urllib_request.Request(url, data=data, headers=headers, method=method)

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
            return body, response
        except urllib_error.HTTPError as e:
            self.module.fail_json(msg=f"HTTP request failed: {e.code} - {e.reason}")
        except urllib_error.URLError as e:
            self.module.fail_json(msg=f"URL error: {e.reason}")

    def login(self):
        """Authenticate to the device and detect model."""
        login_url = f"{self.base_url}/cgi-bin/luci"

        # First GET the login page to detect firmware version and model
        req = urllib_request.Request(login_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
        except Exception as e:
            self.module.fail_json(msg=f"Failed to access login page: {str(e)}")

        # Auto-detect model from login page if not specified
        if not self.model:
            model_match = re.search(r'(WAX\d+)', body)
            if model_match:
                self.model = model_match.group(1)
            else:
                self.model = 'WAX210'  # Default fallback

        # Set model-specific SSID popup endpoint
        # WAX210: wifi_Encryption_P2P, WAX218: wifi_Encryption_Combined
        if self.model == 'WAX218':
            self.ssid_popup_endpoint = '/admin/network/wifi_Encryption_Combined'
        else:
            self.ssid_popup_endpoint = '/admin/network/wifi_Encryption_P2P'

        # Detect if firmware uses SHA-512 (new) or MD5 (old)
        uses_sha512 = 'sha512sum' in body

        # Hash password appropriately
        if uses_sha512:
            hashed_pw = self._hash_password_sha512(self.password)
        else:
            hashed_pw = self._hash_password_md5(self.password)

        # Login - uses 'username' and 'password' fields (works for both models)
        login_data = f"username={self.username}&password={hashed_pw}&agree=1&account={self.username}"

        req = urllib_request.Request(login_url, data=to_bytes(login_data))
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        req.add_header('Referer', f'{self.base_url}/cgi-bin/luci')
        req.add_header('Origin', self.base_url)
        req.add_header('Cookie', 'is_login=1')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
        except Exception as e:
            self.module.fail_json(msg=f"Login request failed: {str(e)}")

        # Extract stok from response
        stok_match = re.search(r';stok=([a-f0-9]+)', body)
        if stok_match:
            self.stok = stok_match.group(1)

        # Verify we have stok
        if self.stok:
            return True

        self.module.fail_json(
            msg="Login failed - could not obtain session token. Check username/password.",
            response_preview=body[:500] if body else "empty"
        )
        return False

    def get_wireless_config(self):
        """Get wireless configuration from the device"""
        if not self.stok:
            self.login()

        # Use minimal network list - just "99" returns all interfaces
        endpoint = f"/cgi-bin/luci/;stok={self.stok}/admin/network/iface_status2/99"
        url = f"{self.base_url}{endpoint}"

        body, response = self._make_request(url)

        try:
            config = json.loads(body)
            return config
        except Exception as e:
            self.module.fail_json(
                msg=f"Failed to parse wireless config: {str(e)}",
                response_body=body[:500] if body else "empty",
                url=url
            )

    def find_ssid_config(self, ssid_name):
        """Find configuration for a specific SSID"""
        config = self.get_wireless_config()

        ssid_configs = []
        for iface in config:
            if isinstance(iface, dict) and iface.get('device', '').startswith('wifi'):
                if iface.get('name') == ssid_name:
                    ssid_configs.append(iface)

        return ssid_configs

    def get_csrf_token(self):
        """Get CSRF token from the device"""
        if not self.stok:
            self.login()

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/system/ajax_getCsrf"
        body, info = self._make_request(url)

        try:
            result = json.loads(body)
            return result.get('val_csrf')
        except Exception:
            return None

    def set_csrf_token(self):
        """Set CSRF token on the device (required before form submission)"""
        if not self.stok:
            self.login()

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/system/ajax_setCsrf"
        body, info = self._make_request(url)
        return True

    def get_wireless_page(self):
        """Get the full wireless configuration page HTML"""
        if not self.stok:
            self.login()

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        body, info = self._make_request(url)
        return body

    def get_ssid_slot(self, ssid_name):
        """Get the slot number for a given SSID name.

        First tries to find from the interface status API, which includes
        the network field. Falls back to searching popup forms.
        """
        if not self.stok:
            self.login()

        # First try to find from interface status
        config = self.get_wireless_config()
        for iface in config:
            if isinstance(iface, dict) and iface.get('name') == ssid_name:
                # Try to find the slot from the network field
                iwdata = iface.get('id', {}).get('iwdata', {})
                network = iwdata.get('network', '')
                # Network can be like 'vlan121' or 'network3' or just 'lan'
                # Check for explicit network number
                slot_match = re.search(r'network(\d+)', network)
                if slot_match:
                    return int(slot_match.group(1))
                # If network is a VLAN name, we need to search popups
                break

        # If static mapping exists and we didn't find via API, try it
        if ssid_name in KNOWN_SSID_SLOTS:
            return KNOWN_SSID_SLOTS[ssid_name]

        # Search popup forms for the SSID
        for slot in range(1, 9):
            params = self._get_popup_params(slot)
            query_string = urlencode(params)
            popup_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}{self.ssid_popup_endpoint}?{query_string}"
            try:
                body, response = self._make_request(popup_url)
                # Look for SSID name in the popup (use id= attribute which has the actual value)
                ssid_match = re.search(rf'id="cbid\.wireless\.wifi0_ssid_{slot}\.ssid"\s+value="([^"]*)"', body)
                if ssid_match and ssid_match.group(1) == ssid_name:
                    return slot
            except Exception:
                continue

        return None

    def build_form_data(self, ssid_name, ssid_slot, params, csrf_token):
        """Build form data for wireless configuration update using popup form structure"""
        # Base form fields required by the popup
        form_data = {
            'form_submit': '1',
            'val_csrf': csrf_token,
            'fromEncr': f'wifi0.network{ssid_slot}',
            'opmode': 'ap',
            'device': '',
            'displayMode': '',
            'is_wifi_join': '',
            'vlan_isolation_enable': '1',
            'wifi0_opmode': '',
            'wifi1_opmode': '',
            'wifi0Disabled_tmp': '',
            'wifi1Disabled_tmp': '',
        }

        # SSID name
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.ssid'] = ssid_name

        # Handle enabled/disabled state for each radio
        # radio param can be: 'both', '2.4ghz', '5ghz', 'none'
        radio = params.get('radio', 'both')
        state = params.get('state', 'present')

        # Default: enable both radios unless state is disabled
        if state in ['disabled', 'absent']:
            wifi0_disabled = '1'
            wifi1_disabled = '1'
        elif radio == '2.4ghz':
            wifi0_disabled = '0'  # 2.4GHz = wifi0
            wifi1_disabled = '1'  # 5GHz = wifi1
        elif radio == '5ghz':
            wifi0_disabled = '1'
            wifi1_disabled = '0'
        elif radio == 'none':
            wifi0_disabled = '1'
            wifi1_disabled = '1'
        else:  # 'both' or default
            wifi0_disabled = '0'
            wifi1_disabled = '0'

        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.disabled'] = wifi0_disabled
        form_data[f'cbid.wireless.wifi1_ssid_{ssid_slot}.disabled'] = wifi1_disabled
        form_data[f'cbi.cbe.wireless.wifi0_ssid_{ssid_slot}.disabled'] = '1'
        form_data[f'cbi.cbe.wireless.wifi1_ssid_{ssid_slot}.disabled'] = '1'

        # Encryption settings
        encryption = params.get('encryption', 'psk2')
        # Strip cipher suffix if provided
        if '+' in encryption:
            enc_type = encryption.split('+')[0]
        else:
            enc_type = encryption
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.encryption'] = enc_type
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.cipher'] = 'ccmp'

        # Passphrase/key - AES encrypt for transmission
        passphrase = params.get('passphrase')
        if passphrase:
            encrypted_passphrase = aes_encrypt_passphrase(passphrase)
            form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.key'] = encrypted_passphrase

        # VLAN configuration
        vlan = params.get('vlan')
        if vlan:
            vlan_id = vlan.replace('vlan', '') if isinstance(vlan, str) and vlan.startswith('vlan') else str(vlan)
            form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.vlan_id'] = vlan_id
            form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.isolation'] = '0'

        # Client isolation
        isolation = params.get('isolation')
        if isolation is not None:
            form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.isolate'] = '1' if isolation else '0'

        # Hidden SSID
        hidden = params.get('hidden')
        if hidden is not None:
            form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.hidden'] = '1' if hidden else '0'

        # Band steering
        band_steering = params.get('band_steering')
        if band_steering is not None:
            form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.bandsteer_en'] = '1' if band_steering else '0'
            if band_steering:
                form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.bandsteerpersent'] = '75'
                form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.bandsteerrssi'] = '-75'

        # Default values for other required fields
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.mode'] = 'ap'
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.wpa_group_rekey'] = '3600'
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.tc_enabled'] = '0'
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.tc_uplimit'] = '0'
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.tc_downlimit'] = '0'
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.l2_isolatior'] = '0'
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.fastroamingEnable'] = '0'
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.acct_enabled'] = '0'

        return form_data

    def get_csrf_from_page(self):
        """Get CSRF token from the wireless configuration page"""
        if not self.stok:
            self.login()

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        req = urllib_request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')

        try:
            response = self.opener.open(req)
            html = response.read().decode('utf-8')
        except Exception as e:
            return None

        # Find CSRF token in the HTML
        patterns = [
            r'name="val_csrf"\s+value="(\d+)"',
            r'val_csrf["\']?\s*[:=]\s*["\']?(\d+)',
            r'id="val_csrf"\s+value="(\d+)"',
            r'<input[^>]*name=["\']val_csrf["\'][^>]*value=["\'](\d+)["\']',
        ]

        for pattern in patterns:
            csrf_match = re.search(pattern, html, re.IGNORECASE)
            if csrf_match:
                return csrf_match.group(1)

        # Generate random if not found
        import random
        return str(random.randint(100000, 999999))

    def get_sysauth_cookie(self):
        """Get the sysauth cookie value"""
        for cookie in self.cookie_jar:
            if cookie.name == 'sysauth':
                return cookie.value
        return None

    def _get_popup_params(self, ssid_slot):
        """Get parameters for the encryption popup page"""
        return {
            'netId': f'wifi0.network{ssid_slot}',
            'displayMode': 'ap',
            'checkbox2G': '1',
            'checkbox5G': '1',
            'guestEn': '0',
            'select_opmode': 'ap',
            'wifi0_select_opmode': 'ap',
            'wifi1_select_opmode': 'ap',
            'countryId': '840',
            'select_hwmode': '11axg',
            'tmpOpmode': 'ap',
        }

    def get_ssid_vlan_via_popup(self, ssid_slot):
        """Get current VLAN for an SSID via the popup form"""
        if not self.stok:
            self.login()

        popup_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}{self.ssid_popup_endpoint}"
        params = self._get_popup_params(ssid_slot)
        query_string = urlencode(params)
        full_url = f"{popup_url}?{query_string}"

        body, response = self._make_request(full_url)
        match = re.search(rf'name="cbid\.wireless\.wifi0_ssid_{ssid_slot}\.vlan_id"\s+value="(\d+)"', body)
        return match.group(1) if match else None

    def get_ssid_config_via_popup(self, ssid_slot):
        """Get full SSID configuration via the popup form.

        Returns dict with: ssid, vlan_id, encryption, key (encrypted), wifi0_disabled, wifi1_disabled
        """
        if not self.stok:
            self.login()

        popup_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}{self.ssid_popup_endpoint}"
        params = self._get_popup_params(ssid_slot)
        query_string = urlencode(params)
        full_url = f"{popup_url}?{query_string}"

        body, response = self._make_request(full_url)

        config = {}

        # Extract key fields using id= attribute (has actual value) or name= for inputs
        fields = [
            ('ssid', rf'id="cbid\.wireless\.wifi0_ssid_{ssid_slot}\.ssid"\s+value="([^"]*)"'),
            ('vlan_id', rf'name="cbid\.wireless\.wifi0_ssid_{ssid_slot}\.vlan_id"\s+value="(\d+)"'),
            ('key', rf'id="cbid\.wireless\.wifi0_ssid_{ssid_slot}\.key"\s+value="([^"]*)"'),
            ('wifi0_disabled', rf'name="cbid\.wireless\.wifi0_ssid_{ssid_slot}\.disabled"[^>]*value="([01])"'),
            ('wifi1_disabled', rf'name="cbid\.wireless\.wifi1_ssid_{ssid_slot}\.disabled"[^>]*value="([01])"'),
        ]

        for field_name, pattern in fields:
            match = re.search(pattern, body, re.IGNORECASE)
            config[field_name] = match.group(1) if match else None

        # Encryption - find checked radio button
        enc_pattern = rf'name="cbid\.wireless\.wifi0_ssid_{ssid_slot}\.encryption"[^>]*value="([^"]*)"[^>]*checked'
        enc_match = re.search(enc_pattern, body, re.IGNORECASE)
        config['encryption'] = enc_match.group(1) if enc_match else None

        # Derive radio setting
        wifi0_on = config.get('wifi0_disabled') == '0'
        wifi1_on = config.get('wifi1_disabled') == '0'
        if wifi0_on and wifi1_on:
            config['radio'] = 'both'
        elif wifi0_on:
            config['radio'] = '2.4ghz'
        elif wifi1_on:
            config['radio'] = '5ghz'
        else:
            config['radio'] = 'none'

        return config

    def set_ssid_vlan_via_popup(self, ssid_slot, new_vlan):
        """Set VLAN for an SSID using the popup form approach (proven to work)"""
        if not self.stok:
            self.login()

        popup_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}{self.ssid_popup_endpoint}"
        params = self._get_popup_params(ssid_slot)
        query_string = urlencode(params)
        full_url = f"{popup_url}?{query_string}"

        # GET the popup form
        body, response = self._make_request(full_url)

        # Parse form using regex (BeautifulSoup not available in Ansible)
        # Note: action attribute may use single or double quotes
        form_action_match = re.search(r'<form[^>]*name="guestNetworkEncryption"[^>]*action=[\'"]([^\'"]+)[\'"]', body)
        if not form_action_match:
            return False, "Could not find encryption form"

        form_action = form_action_match.group(1)

        # Get current VLAN
        vlan_key = f'cbid.wireless.wifi0_ssid_{ssid_slot}.vlan_id'
        vlan_match = re.search(rf'name="{re.escape(vlan_key)}"\s+value="(\d+)"', body)
        old_vlan = vlan_match.group(1) if vlan_match else 'unknown'

        # Collect all form fields using regex
        form_data = {}

        # Find all input fields
        for match in re.finditer(r'<input[^>]*>', body, re.IGNORECASE):
            inp = match.group(0)
            name_match = re.search(r'name="([^"]+)"', inp)
            if not name_match:
                continue
            name = name_match.group(1)
            value_match = re.search(r'value="([^"]*)"', inp)
            value = value_match.group(1) if value_match else ''
            type_match = re.search(r'type="([^"]+)"', inp)
            inp_type = type_match.group(1) if type_match else 'text'

            if inp_type == 'checkbox':
                if 'checked' in inp:
                    form_data[name] = value
            elif inp_type == 'radio':
                if 'checked' in inp:
                    form_data[name] = value
            else:
                form_data[name] = value

        # Find all select fields with selected options
        for match in re.finditer(r'<select[^>]*name="([^"]+)"[^>]*>(.*?)</select>', body, re.DOTALL | re.IGNORECASE):
            name = match.group(1)
            options = match.group(2)
            selected_match = re.search(r'<option[^>]*selected[^>]*value="([^"]*)"', options, re.IGNORECASE)
            if selected_match:
                form_data[name] = selected_match.group(1)

        # Set form_submit and new VLAN
        form_data['form_submit'] = '1'
        form_data[vlan_key] = str(new_vlan)

        # POST the form
        post_url = f"{self.base_url}{form_action}"
        encoded_data = urlencode(form_data).encode()

        req = urllib_request.Request(post_url, data=encoded_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Referer', full_url)
        req.add_header('Origin', self.base_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
            return True, {'old_vlan': old_vlan, 'new_vlan': str(new_vlan)}
        except urllib_error.HTTPError as e:
            return False, f"HTTP error: {e.code} - {e.reason}"
        except Exception as e:
            return False, f"Error: {str(e)}"

    def configure_ssid_via_popup(self, ssid_slot, ssid_name, params):
        """Configure an SSID using the popup form approach.

        This method handles all SSID configuration: VLAN, encryption, passphrase, radios.

        Args:
            ssid_slot: The SSID slot number (1-8)
            ssid_name: The SSID name
            params: Dict with configuration:
                - vlan: VLAN ID (e.g., 121 or 'vlan121')
                - encryption: 'psk2', 'sae-mixed', etc.
                - passphrase: WiFi password (will be AES encrypted)
                - radio: 'both', '2.4ghz', '5ghz', 'none'
                - hidden: bool for hidden SSID
                - isolation: bool for client isolation

        Returns:
            tuple: (success: bool, result: dict/str)
        """
        if not self.stok:
            self.login()

        popup_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}{self.ssid_popup_endpoint}"
        popup_params = self._get_popup_params(ssid_slot)
        query_string = urlencode(popup_params)
        full_url = f"{popup_url}?{query_string}"

        # GET the popup form
        body, response = self._make_request(full_url)

        # Parse form action
        form_action_match = re.search(r'<form[^>]*name="guestNetworkEncryption"[^>]*action=[\'"]([^\'"]+)[\'"]', body)
        if not form_action_match:
            return False, "Could not find encryption form"

        form_action = form_action_match.group(1)

        # Collect current form fields
        form_data = {}

        # Find all input fields
        for match in re.finditer(r'<input[^>]*>', body, re.IGNORECASE):
            inp = match.group(0)
            name_match = re.search(r'name="([^"]+)"', inp)
            if not name_match:
                continue
            name = name_match.group(1)
            value_match = re.search(r'value="([^"]*)"', inp)
            value = value_match.group(1) if value_match else ''
            type_match = re.search(r'type="([^"]+)"', inp)
            inp_type = type_match.group(1) if type_match else 'text'

            if inp_type == 'checkbox':
                if 'checked' in inp:
                    form_data[name] = value
            elif inp_type == 'radio':
                if 'checked' in inp:
                    form_data[name] = value
            else:
                form_data[name] = value

        # Find all select fields with selected options
        for match in re.finditer(r'<select[^>]*name="([^"]+)"[^>]*>(.*?)</select>', body, re.DOTALL | re.IGNORECASE):
            name = match.group(1)
            options = match.group(2)
            selected_match = re.search(r'<option[^>]*selected[^>]*value="([^"]*)"', options, re.IGNORECASE)
            if selected_match:
                form_data[name] = selected_match.group(1)

        # Track changes
        changes = []

        # Apply VLAN change
        vlan = params.get('vlan')
        if vlan:
            vlan_id = vlan.replace('vlan', '') if isinstance(vlan, str) and vlan.startswith('vlan') else str(vlan)
            vlan_key = f'cbid.wireless.wifi0_ssid_{ssid_slot}.vlan_id'
            old_vlan = form_data.get(vlan_key, 'unknown')
            if old_vlan != vlan_id:
                changes.append(f'VLAN: {old_vlan} -> {vlan_id}')
            form_data[vlan_key] = vlan_id

        # Apply encryption change
        encryption = params.get('encryption')
        if encryption:
            enc_type = encryption.split('+')[0] if '+' in encryption else encryption
            enc_key = f'cbid.wireless.wifi0_ssid_{ssid_slot}.encryption'
            old_enc = form_data.get(enc_key, 'unknown')
            if old_enc != enc_type:
                changes.append(f'encryption: {old_enc} -> {enc_type}')
            form_data[enc_key] = enc_type
            form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.cipher'] = 'ccmp'

        # Apply passphrase change (AES encrypted)
        passphrase = params.get('passphrase')
        if passphrase:
            encrypted_passphrase = aes_encrypt_passphrase(passphrase)
            key_field = f'cbid.wireless.wifi0_ssid_{ssid_slot}.key'
            form_data[key_field] = encrypted_passphrase
            changes.append('passphrase: updated')

        # Apply radio enable/disable
        radio = params.get('radio', 'both')
        wifi0_key = f'cbid.wireless.wifi0_ssid_{ssid_slot}.disabled'
        wifi1_key = f'cbid.wireless.wifi1_ssid_{ssid_slot}.disabled'
        old_wifi0 = form_data.get(wifi0_key, '0')
        old_wifi1 = form_data.get(wifi1_key, '0')

        if radio == '2.4ghz':
            new_wifi0, new_wifi1 = '0', '1'
        elif radio == '5ghz':
            new_wifi0, new_wifi1 = '1', '0'
        elif radio == 'none':
            new_wifi0, new_wifi1 = '1', '1'
        else:  # 'both'
            new_wifi0, new_wifi1 = '0', '0'

        if old_wifi0 != new_wifi0 or old_wifi1 != new_wifi1:
            old_radios = []
            if old_wifi0 == '0':
                old_radios.append('2.4GHz')
            if old_wifi1 == '0':
                old_radios.append('5GHz')
            new_radios = []
            if new_wifi0 == '0':
                new_radios.append('2.4GHz')
            if new_wifi1 == '0':
                new_radios.append('5GHz')
            changes.append(f'radios: {",".join(old_radios) or "none"} -> {",".join(new_radios) or "none"}')

        form_data[wifi0_key] = new_wifi0
        form_data[wifi1_key] = new_wifi1
        form_data[f'cbi.cbe.wireless.wifi0_ssid_{ssid_slot}.disabled'] = '1'
        form_data[f'cbi.cbe.wireless.wifi1_ssid_{ssid_slot}.disabled'] = '1'

        # Set SSID name
        form_data[f'cbid.wireless.wifi0_ssid_{ssid_slot}.ssid'] = ssid_name

        # Set form_submit
        form_data['form_submit'] = '1'

        # POST the form
        post_url = f"{self.base_url}{form_action}"
        encoded_data = urlencode(form_data).encode()

        req = urllib_request.Request(post_url, data=encoded_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Referer', full_url)
        req.add_header('Origin', self.base_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
            return True, {'changes': changes, 'ssid': ssid_name, 'slot': ssid_slot}
        except urllib_error.HTTPError as e:
            return False, f"HTTP error: {e.code} - {e.reason}"
        except Exception as e:
            return False, f"Error: {str(e)}"

    def apply_configuration(self, form_data):
        """Submit the configuration form using popup-style submission and apply changes.

        The LuCI interface uses a two-step process:
        1. POST to wireless_device endpoint (saves changes to staging)
        2. POST to saveapply endpoint (applies staged changes)
        """
        if not self.stok:
            self.login()

        sysauth = self.get_sysauth_cookie()

        # Step 1: Submit form to wireless_device endpoint (like popup Save button)
        submit_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        encoded_data = urlencode(form_data).encode()

        req = urllib_request.Request(submit_url, data=encoded_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Referer', f'{self.base_url}/cgi-bin/luci/;stok={self.stok}{self.ssid_popup_endpoint}')
        req.add_header('Origin', self.base_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        if sysauth:
            req.add_header('Cookie', f'sysauth={sysauth}')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
            if response.status != 200:
                return False, f"Form submission failed: status {response.status}"
        except urllib_error.HTTPError as e:
            return False, f"Form submission HTTP error: {e.code} - {e.reason}"
        except Exception as e:
            return False, f"Form submission error: {str(e)}"

        # Step 2: Apply changes using saveapply endpoint
        apply_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/uci/saveapply"
        apply_data = {
            'form_submit': '1',
            'val_csrf': form_data.get('val_csrf', ''),
            'submitType': '2',
            'saveApply': '',
        }
        apply_encoded = urlencode(apply_data).encode()

        req = urllib_request.Request(apply_url, data=apply_encoded, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Referer', submit_url)
        req.add_header('Origin', self.base_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        if sysauth:
            req.add_header('Cookie', f'sysauth={sysauth}')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
            if response.status == 200:
                return True, "Configuration applied successfully"
            return False, f"Apply failed: status {response.status}"
        except urllib_error.HTTPError as e:
            return False, f"Apply HTTP error: {e.code} - {e.reason}"
        except Exception as e:
            return False, f"Apply error: {str(e)}"

    def apply_and_reload(self, form_data):
        """Submit configuration - wrapper for apply_configuration"""
        return self.apply_configuration(form_data)


def main():
    module_args = dict(
        host=dict(type='str', required=True),
        username=dict(type='str', required=False, default='admin'),
        password=dict(type='str', required=True, no_log=True),
        ssid_name=dict(type='str', required=True),
        state=dict(type='str', required=False, default='present',
                   choices=['present', 'absent', 'enabled', 'disabled']),
        radio=dict(type='str', required=False, default='both',
                   choices=['2.4ghz', '5ghz', 'both']),
        encryption=dict(type='str', required=False,
                        choices=['none', 'psk2', 'psk2+ccmp', 'sae-mixed', 'sae-mixed+ccmp']),
        passphrase=dict(type='str', required=False, no_log=True),
        vlan=dict(type='str', required=False),
        isolation=dict(type='bool', required=False),
        hidden=dict(type='bool', required=False),
        band_steering=dict(type='bool', required=False),
        validate_certs=dict(type='bool', required=False, default=False),
        model=dict(type='str', required=False, default=None,
                   choices=['WAX210', 'WAX218', None]),
    )

    result = dict(
        changed=False,
        config={},
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Create API instance
    api = WAX210API(module)

    # Login to device
    if not api.login():
        module.fail_json(msg='Failed to login to device', **result)

    # Get current configuration for the SSID
    ssid_name = module.params['ssid_name']
    ssid_configs = api.find_ssid_config(ssid_name)

    # Build current config response
    if ssid_configs:
        result['config'] = {
            'ssid_name': ssid_name,
            'found': True,
            'interfaces': []
        }

        for config in ssid_configs:
            iwdata = config.get('id', {}).get('iwdata', {})
            iface_info = {
                'device': config.get('device'),
                'radio': '2.4ghz' if config.get('device') == 'wifi0' else '5ghz',
                'enabled': iwdata.get('disabled', '0') == '0',
                'ssid': iwdata.get('ssid'),
                'encryption': config.get('encr'),
                'vlan': iwdata.get('network'),
                'vlan_id': iwdata.get('vlan_id'),
                'isolation': iwdata.get('isolation') == '1',
                'hidden': iwdata.get('hidden') == '1',
                'band_steering': iwdata.get('bandsteer_en') == '1',
            }
            result['config']['interfaces'].append(iface_info)

        result['message'] = f"SSID '{ssid_name}' found on {len(ssid_configs)} interface(s)"
    else:
        result['config'] = {
            'ssid_name': ssid_name,
            'found': False
        }
        result['message'] = f"SSID '{ssid_name}' not found"

    # Determine if changes are needed
    state = module.params['state']
    needs_change = False
    change_reasons = []

    # Check if state change is needed
    if ssid_configs:
        current_enabled = any(
            cfg.get('id', {}).get('iwdata', {}).get('disabled', '0') == '0'
            for cfg in ssid_configs
        )
        if state in ['disabled', 'absent'] and current_enabled:
            needs_change = True
            change_reasons.append("disable SSID")
        elif state in ['enabled', 'present'] and not current_enabled:
            needs_change = True
            change_reasons.append("enable SSID")

        # Check VLAN change - use popup method for accurate current value
        desired_vlan = module.params.get('vlan')
        if desired_vlan:
            desired_vlan_id = desired_vlan.replace('vlan', '') if desired_vlan.startswith('vlan') else desired_vlan
            # Get SSID slot and check VLAN via popup (more accurate than iface_status)
            ssid_slot = api.get_ssid_slot(ssid_name)
            if ssid_slot:
                current_vlan_id = api.get_ssid_vlan_via_popup(ssid_slot)
                if current_vlan_id and str(current_vlan_id) != str(desired_vlan_id):
                    needs_change = True
                    change_reasons.append(f"change VLAN from {current_vlan_id} to {desired_vlan_id}")
            else:
                # Fallback to iface_status data
                for cfg in ssid_configs:
                    current_vlan_id = cfg.get('id', {}).get('iwdata', {}).get('vlan_id', '')
                    if str(current_vlan_id) != str(desired_vlan_id):
                        needs_change = True
                        change_reasons.append(f"change VLAN from {current_vlan_id} to {desired_vlan_id}")
                        break

    elif state in ['present', 'enabled']:
        # SSID not found but should exist - would need to be created
        needs_change = True
        change_reasons.append("create SSID")

    # If check mode, report what would change
    if module.check_mode:
        if needs_change:
            result['changed'] = True
            result['message'] = f"Would {', '.join(change_reasons)}"
        module.exit_json(**result)

    # Apply changes if needed
    if needs_change:
        # Get the SSID slot number
        ssid_slot = api.get_ssid_slot(ssid_name)
        if not ssid_slot:
            module.fail_json(msg=f"Could not determine slot for SSID '{ssid_name}'", **result)

        # Check if this is a VLAN-only change - use popup method (proven to work)
        desired_vlan = module.params.get('vlan')
        vlan_change_only = (
            desired_vlan and
            len(change_reasons) == 1 and
            'change VLAN' in change_reasons[0]
        )

        if vlan_change_only:
            # Use the popup-based VLAN change method (proven to work)
            desired_vlan_id = desired_vlan.replace('vlan', '') if desired_vlan.startswith('vlan') else desired_vlan
            success, msg = api.set_ssid_vlan_via_popup(ssid_slot, desired_vlan_id)

            if success:
                # Verify the change
                new_vlan = api.get_ssid_vlan_via_popup(ssid_slot)
                if str(new_vlan) == str(desired_vlan_id):
                    result['changed'] = True
                    result['message'] = f"VLAN changed from {msg['old_vlan']} to {msg['new_vlan']}"
                else:
                    module.fail_json(
                        msg=f"VLAN change verification failed: expected {desired_vlan_id}, got {new_vlan}",
                        **result
                    )
            else:
                module.fail_json(msg=f"VLAN change failed: {msg}", **result)
        else:
            # Use the standard form-based approach for other changes
            csrf_token = api.get_csrf_token()
            if not csrf_token:
                module.fail_json(msg="Could not obtain CSRF token", **result)

            form_data = api.build_form_data(ssid_name, ssid_slot, module.params, csrf_token)
            success, msg = api.apply_and_reload(form_data)

            if success:
                result['changed'] = True
                result['message'] = f"Configuration applied: {', '.join(change_reasons)}"
            else:
                module.fail_json(msg=f"Configuration failed: {msg}", **result)

        # Re-read config to show final state
        ssid_configs = api.find_ssid_config(ssid_name)
        if ssid_configs:
            result['config']['interfaces'] = []
            for config in ssid_configs:
                iwdata = config.get('id', {}).get('iwdata', {})
                iface_info = {
                    'device': config.get('device'),
                    'radio': '2.4ghz' if config.get('device') == 'wifi0' else '5ghz',
                    'enabled': iwdata.get('disabled', '0') == '0',
                    'ssid': iwdata.get('ssid'),
                    'encryption': config.get('encr'),
                    'vlan': iwdata.get('network'),
                    'vlan_id': iwdata.get('vlan_id'),
                    'isolation': iwdata.get('isolation') == '1',
                    'hidden': iwdata.get('hidden') == '1',
                    'band_steering': iwdata.get('bandsteer_en') == '1',
                }
                result['config']['interfaces'].append(iface_info)

    module.exit_json(**result)


if __name__ == '__main__':
    main()

