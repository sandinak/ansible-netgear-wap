#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Ansible Netgear WAP Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: netgear_wax_radio
short_description: Manage Netgear WAX210 radio/channel configuration
version_added: "1.0.0"
description:
    - Manage radio configuration on Netgear WAX210 access points
    - Configure channel settings for 2.4GHz and 5GHz radios
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
    channel_2g:
        description: Channel for 2.4GHz radio (auto, 1-11)
        required: false
        type: str
    channel_5g:
        description: Channel for 5GHz radio (36, 40, 44, 48, 52, 56, 60, 64, 100-165)
        required: false
        type: str
    validate_certs:
        description: Validate SSL certificates
        required: false
        type: bool
        default: false
author:
    - Ansible Netgear WAP Project
'''

EXAMPLES = r'''
# Set 5GHz channel to 36
- name: Set 5GHz channel
  netgear_wax210_radio:
    host: 172.19.4.10
    password: your_password_here
    channel_5g: "36"

# Set both channels
- name: Set both radio channels
  netgear_wax210_radio:
    host: 172.19.4.10
    password: your_password_here
    channel_2g: "auto"
    channel_5g: "44"

# Get current radio configuration (check mode)
- name: Get radio config
  netgear_wax210_radio:
    host: 172.19.4.10
    password: your_password_here
  check_mode: true
  register: radio_config
'''

RETURN = r'''
changed:
    description: Whether the configuration was changed
    type: bool
    returned: always
config:
    description: Current radio configuration
    type: dict
    returned: always
    contains:
        wifi0_channel:
            description: Current 2.4GHz channel
            type: str
        wifi1_channel:
            description: Current 5GHz channel
            type: str
message:
    description: Status message
    type: str
    returned: always
'''

import json
import re

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

# Valid channel options
CHANNELS_24GHZ = ['auto', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
CHANNELS_5GHZ = ['auto', '36', '40', '44', '48', '52', '56', '60', '64', '100', '104', '108',
                 '112', '116', '120', '124', '128', '132', '136', '140', '144', '149',
                 '153', '157', '161', '165']


class WAX210RadioAPI(WAXBaseAPI):
    """API class for WAX radio configuration - extends base class"""

    def get_radio_config(self):
        """Get current radio configuration (channels)"""
        if not self.stok:
            if not self.login():
                return {}

        url = f'{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device'
        body, response = self._make_request(url)

        if body is None:
            return {}

        config = {}
        patterns = [
            (r'channel_wifi0_val="([^"]*)"', 'wifi0_channel'),
            (r'channel_wifi1_val="([^"]*)"', 'wifi1_channel'),
        ]
        for pattern, name in patterns:
            match = re.search(pattern, body)
            config[name] = match.group(1) if match else None
        return config

    def set_channels(self, channel_2g=None, channel_5g=None):
        """Set channel(s) for radio(s)

        Args:
            channel_2g: Channel for 2.4GHz (None to keep current)
            channel_5g: Channel for 5GHz (None to keep current)

        Returns:
            tuple: (success: bool, message: str)
        """
        if not self.stok:
            if not self.login():
                return False, "Login failed"

        # Get current values for any channels not being changed
        current = self.get_radio_config()
        new_ch0 = channel_2g if channel_2g else current.get('wifi0_channel', 'auto')
        new_ch1 = channel_5g if channel_5g else current.get('wifi1_channel', '36')

        # Determine status based on channel value
        ch0_status = '1' if new_ch0 == 'auto' else '4'
        ch1_status = '1' if new_ch1 == 'auto' else '4'

        # Get CSRF token
        csrf_token = self.get_csrf_token() or ''

        wifi_channel_data = {
            'submitFlag': '1',
            'disable_radio2G': '0',
            'channel_enable2G': '0',
            'channel2G': new_ch0,
            'channel_list2G': new_ch0,
            'channel_status2G': ch0_status,
            'channel_group2G': '0',
            'disable_radio5G': '0',
            'channel_enable5G': '0',
            'channel5G': new_ch1,
            'channel_list5G': new_ch1,
            'channel_status5G': ch1_status,
            'channel_group5G': '0',
            'form_submit': '1',
            'val_csrf': csrf_token,
        }

        # Call set_csrf to prepare for form submission (browser does this)
        self.set_csrf_token()

        # POST to wifi_Channel endpoint
        channel_url = f'{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wifi_Channel'
        body, response = self._make_request(channel_url, data=wifi_channel_data, method='POST')

        if body is None:
            error_code = getattr(response, 'code', 'unknown') if response else 'unknown'
            return False, f"wifi_Channel failed: {error_code}"

        # Apply changes using base class method
        self.apply_changes()

        return True, f"Channels set: 2.4GHz={new_ch0}, 5GHz={new_ch1}"


def main():
    module_args = dict(
        host=dict(type='str', required=True),
        username=dict(type='str', required=False, default='admin'),
        password=dict(type='str', required=True, no_log=True),
        channel_2g=dict(type='str', required=False),
        channel_5g=dict(type='str', required=False),
        validate_certs=dict(type='bool', required=False, default=False),
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

    if not HAS_WAX_API:
        module.fail_json(msg='Failed to import WAXBaseAPI from module_utils', **result)

    # Validate channel values
    channel_2g = module.params.get('channel_2g')
    channel_5g = module.params.get('channel_5g')

    if channel_2g and channel_2g not in CHANNELS_24GHZ:
        module.fail_json(msg=f"Invalid 2.4GHz channel: {channel_2g}. Valid: {CHANNELS_24GHZ}", **result)
    if channel_5g and channel_5g not in CHANNELS_5GHZ:
        module.fail_json(msg=f"Invalid 5GHz channel: {channel_5g}. Valid: {CHANNELS_5GHZ}", **result)

    # Create API instance and login
    api = WAX210RadioAPI(module)
    if not api.login():
        module.fail_json(msg='Failed to login to device', **result)

    # Get current configuration
    current_config = api.get_radio_config()
    result['config'] = current_config

    # Determine if changes are needed
    needs_change = False
    change_reasons = []

    if channel_2g and current_config.get('wifi0_channel') != channel_2g:
        needs_change = True
        change_reasons.append(f"2.4GHz: {current_config.get('wifi0_channel')} -> {channel_2g}")

    if channel_5g and current_config.get('wifi1_channel') != channel_5g:
        needs_change = True
        change_reasons.append(f"5GHz: {current_config.get('wifi1_channel')} -> {channel_5g}")

    if not needs_change:
        result['message'] = "No changes needed"
        module.exit_json(**result)

    # Check mode - report what would change
    if module.check_mode:
        result['changed'] = True
        result['message'] = f"Would change: {', '.join(change_reasons)}"
        module.exit_json(**result)

    # Apply changes
    success, msg = api.set_channels(channel_2g, channel_5g)

    if success:
        result['changed'] = True
        result['message'] = f"Changed: {', '.join(change_reasons)}"
        # Re-read config to show final state
        result['config'] = api.get_radio_config()
    else:
        module.fail_json(msg=f"Configuration failed: {msg}", **result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()

