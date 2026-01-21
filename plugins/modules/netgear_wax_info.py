#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: netgear_wax_info
short_description: Get information from Netgear WAX210 wireless access point
version_added: "1.0.0"
description:
    - Retrieve wireless SSID configuration from Netgear WAX210 access points
options:
    host:
        description: IP address or hostname of the WAX210 access point
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
        description: Name of the SSID to retrieve (optional, returns all if not specified)
        required: false
        type: str
author:
    - Ansible Netgear WAP Project
'''

EXAMPLES = r'''
# Get all wireless configuration
- name: Get all wireless config
  netgear_wax210_info:
    host: 172.19.4.10
    password: your_password_here
  register: all_config

# Get specific SSID configuration
- name: Get VOV SSID config
  netgear_wax210_info:
    host: 172.19.4.10
    password: your_password_here
    ssid_name: VOV
  register: vov_config
'''

RETURN = r'''
ssids:
    description: List of SSID configurations
    type: list
    returned: always
'''

import json

from ansible.module_utils.basic import AnsibleModule

# Import shared base class - try Ansible collection path first, then direct import for testing
try:
    from ansible_collections.sandinak.netgear_wap.plugins.module_utils.wax_api import WAXBaseAPI
    HAS_WAX_API = True
except ImportError:
    try:
        # Fallback for direct execution (testing)
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'module_utils'))
        from wax_api import WAXBaseAPI
        HAS_WAX_API = True
    except ImportError:
        HAS_WAX_API = False


class WAXInfoAPI(WAXBaseAPI):
    """API client for WAX info (read-only) operations."""

    def get_wireless_config(self):
        """Get wireless configuration from the device.

        Returns:
            list: List of interface configurations
        """
        if not self.stok:
            if not self.login():
                self.module.fail_json(msg="Login failed")

        # Use minimal "99" which returns all interfaces
        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/iface_status2/99"
        body, response = self._make_request(url)

        if body is None:
            self.module.fail_json(msg="Failed to get wireless config")

        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            self.module.fail_json(msg=f"Failed to parse JSON response: {str(e)}")

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            username=dict(type='str', required=False, default='admin'),
            password=dict(type='str', required=True, no_log=True),
            ssid_name=dict(type='str', required=False),
            validate_certs=dict(type='bool', required=False, default=False),
        ),
        supports_check_mode=True
    )

    if not HAS_WAX_API:
        module.fail_json(msg="Failed to import WAXBaseAPI from module_utils")

    ssid_name = module.params.get('ssid_name')

    # Use the shared API class
    api = WAXInfoAPI(module)

    # Get configuration
    config = api.get_wireless_config()

    # Filter for wireless interfaces only
    ssids = []
    for iface in config:
        if isinstance(iface, dict) and iface.get('device', '').startswith('wifi'):
            iwdata = iface.get('id', {}).get('iwdata', {})
            ssid_info = {
                'name': iface.get('name'),
                'device': iface.get('device'),
                'radio': '2.4ghz' if iface.get('device') == 'wifi0' else '5ghz',
                'enabled': iwdata.get('disabled', '0') == '0',
                'ssid': iwdata.get('ssid'),
                'encryption': iface.get('encr'),
                'vlan': iwdata.get('network'),
                'vlan_id': iwdata.get('vlan_id'),
                'isolation': iwdata.get('isolation') == '1',
                'hidden': iwdata.get('hidden') == '1',
                'band_steering': iwdata.get('bandsteer_en') == '1',
                'passphrase': iwdata.get('key', iwdata.get('sae_password')),
            }

            # Filter by SSID name if specified
            if ssid_name is None or iface.get('name') == ssid_name:
                ssids.append(ssid_info)

    module.exit_json(changed=False, ssids=ssids)

if __name__ == '__main__':
    main()

