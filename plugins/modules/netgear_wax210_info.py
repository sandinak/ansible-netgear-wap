#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: netgear_wax210_info
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
    password: ***REMOVED***
  register: all_config

# Get specific SSID configuration
- name: Get VOV SSID config
  netgear_wax210_info:
    host: 172.19.4.10
    password: ***REMOVED***
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
import hashlib
import re
import ssl

try:
    import urllib.request as urllib_request
    import urllib.error as urllib_error
    from urllib.parse import urljoin
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes

def hash_password_md5(password):
    """Hash password with MD5 (old firmware)"""
    return hashlib.md5(to_bytes(password + "\n")).hexdigest()

def hash_password_sha512(password):
    """Hash password with SHA-512 (new firmware 1.1.0.34+)"""
    return hashlib.sha512(to_bytes(password + "\n")).hexdigest()

def login_and_get_config(module, host, username, password):
    """Login to device and get wireless configuration"""
    base_url = f"https://{host}"

    # Create SSL context that doesn't verify certificates
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Create cookie jar and opener
    import http.cookiejar
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib_request.build_opener(
        urllib_request.HTTPCookieProcessor(cookie_jar),
        urllib_request.HTTPSHandler(context=ctx)
    )

    # First GET the login page to detect firmware version
    login_url = f"{base_url}/cgi-bin/luci"
    try:
        req = urllib_request.Request(login_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        response = opener.open(req)
        body = response.read().decode('utf-8')

        # Detect if firmware uses SHA-512 (new) or MD5 (old)
        uses_sha512 = 'sha512sum' in body

        # Hash password appropriately
        if uses_sha512:
            hashed_pw = hash_password_sha512(password)
        else:
            hashed_pw = hash_password_md5(password)

        # Login - new firmware requires both 'username' and 'account' parameters
        login_data = f"username={username}&password={hashed_pw}&agree=1&account={username}"

        req = urllib_request.Request(login_url, data=to_bytes(login_data))
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        req.add_header('Referer', f'{base_url}/cgi-bin/luci')
        req.add_header('Origin', base_url)
        req.add_header('Cookie', 'is_login=1')
        response = opener.open(req)
        body = response.read().decode('utf-8')

        # Extract stok from response
        stok_match = re.search(r';stok=([a-f0-9]+)', body)
        if not stok_match:
            module.fail_json(msg="Login failed - could not obtain session token. Check username/password.")
        
        stok = stok_match.group(1)
        
        # Get wireless configuration
        config_url = f"{base_url}/cgi-bin/luci/;stok={stok}/admin/network/iface_status2/99,app,guest,lan,mgmt,vlan116,vlan119,vlan121"
        req = urllib_request.Request(config_url)
        response = opener.open(req)
        config_body = response.read().decode('utf-8')
        
        config = json.loads(config_body)
        return config
        
    except urllib_error.URLError as e:
        module.fail_json(msg=f"HTTP request failed: {str(e)}")
    except json.JSONDecodeError as e:
        module.fail_json(msg=f"Failed to parse JSON response: {str(e)}")
    except Exception as e:
        module.fail_json(msg=f"Unexpected error: {str(e)}")

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            username=dict(type='str', required=False, default='admin'),
            password=dict(type='str', required=True, no_log=True),
            ssid_name=dict(type='str', required=False),
        ),
        supports_check_mode=True
    )
    
    if not HAS_URLLIB:
        module.fail_json(msg="urllib is required for this module")
    
    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    ssid_name = module.params.get('ssid_name')
    
    # Get configuration
    config = login_and_get_config(module, host, username, password)
    
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

