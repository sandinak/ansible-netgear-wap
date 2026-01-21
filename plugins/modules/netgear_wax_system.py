#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Ansible Netgear WAP Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: netgear_wax_system
short_description: Configure Netgear WAX210 system-level settings
version_added: "1.0.0"
description:
    - Configure system-level settings on Netgear WAX210 access points
    - Set AP Name (device name)
    - Enable/disable Management Interface on 2.4GHz and 5GHz
    - Future: SNMP, SSH, CLI settings
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
    ap_name:
        description: Access point name (max 15 characters)
        required: false
        type: str
    mgmt_interface_2g:
        description: Enable/disable Management Interface on 2.4GHz radio
        required: false
        type: bool
    mgmt_interface_5g:
        description: Enable/disable Management Interface on 5GHz radio
        required: false
        type: bool
    validate_certs:
        description: Validate SSL certificates
        required: false
        type: bool
        default: false
author:
    - Ansible Netgear WAP Project
'''

EXAMPLES = r'''
# Set AP Name
- name: Set AP name to POD1-WAP
  netgear_wax210_system:
    host: 172.19.4.11
    password: "{{ wap_password }}"
    ap_name: POD1-WAP

# Disable Management Interface on both radios
- name: Disable management interface
  netgear_wax210_system:
    host: 172.19.4.11
    password: "{{ wap_password }}"
    mgmt_interface_2g: false
    mgmt_interface_5g: false

# Configure AP name and disable management interface
- name: Full system config
  netgear_wax210_system:
    host: 172.19.4.11
    password: "{{ wap_password }}"
    ap_name: POD2-WAP
    mgmt_interface_2g: false
    mgmt_interface_5g: false
'''

RETURN = r'''
changed:
    description: Whether configuration was changed
    type: bool
    returned: always
message:
    description: Status message
    type: str
    returned: always
config:
    description: Current configuration after changes
    type: dict
    returned: always
    contains:
        ap_name:
            description: Current AP name
            type: str
        mgmt_interface_2g:
            description: Management interface 2.4GHz enabled state
            type: bool
        mgmt_interface_5g:
            description: Management interface 5GHz enabled state
            type: bool
'''

import json
import hashlib
import re
import ssl
import time

try:
    import urllib.request as urllib_request
    import urllib.error as urllib_error
    import urllib.parse as urllib_parse
    from urllib.parse import urljoin
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes

class WAX210SystemAPI:
    """API client for WAX210 system-level configuration"""

    def __init__(self, module):
        self.module = module
        self.host = module.params['host']
        self.username = module.params.get('username', 'admin')
        self.password = module.params['password']
        self.base_url = None  # Will be set by _detect_protocol
        self.stok = None
        self.sysauth = None
        self.opener = None
        self._setup_opener()
        self._detect_protocol()

    def _setup_opener(self):
        """Setup urllib opener with SSL context and cookies"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        import http.cookiejar
        cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib_request.build_opener(
            urllib_request.HTTPCookieProcessor(cookie_jar),
            urllib_request.HTTPSHandler(context=ctx)
        )
        self.cookie_jar = cookie_jar

    def _detect_protocol(self):
        """Auto-detect whether to use HTTP or HTTPS"""
        # Try HTTPS first, then fall back to HTTP
        for protocol in ['https', 'http']:
            try:
                test_url = f"{protocol}://{self.host}/cgi-bin/luci"
                req = urllib_request.Request(test_url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                self.opener.open(req, timeout=5)
                self.base_url = f"{protocol}://{self.host}"
                return
            except Exception:
                continue
        # Default to HTTPS if both fail (will error later with better message)
        self.base_url = f"https://{self.host}"

    def _hash_password_sha512(self, password):
        """Hash password using SHA512 (newer firmware)"""
        return hashlib.sha512(to_bytes(password + "\n")).hexdigest()

    def _hash_password_md5(self, password):
        """Hash password using MD5 (older firmware/WAX218)"""
        return hashlib.md5(to_bytes(password + "\n")).hexdigest()

    def _make_request(self, url, data=None, method='GET'):
        """Make HTTP request and return response body"""
        if data:
            encoded_data = urllib_parse.urlencode(data).encode()
            req = urllib_request.Request(url, data=encoded_data, method=method)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        else:
            req = urllib_request.Request(url)

        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        req.add_header('Referer', f'{self.base_url}/cgi-bin/luci')
        req.add_header('Origin', self.base_url)
        if self.sysauth:
            req.add_header('Cookie', f'sysauth={self.sysauth}; is_login=1')

        response = self.opener.open(req)
        return response.read().decode('utf-8'), response

    def wait_for_ready(self, timeout=30, check_interval=2):
        """Wait for device to be ready after applying changes.

        Polls the login page until responsive or timeout.
        Returns True if device is ready, False if timeout.
        """
        import time as time_module
        start_time = time_module.time()

        while time_module.time() - start_time < timeout:
            try:
                req = urllib_request.Request(f"{self.base_url}/cgi-bin/luci")
                req.add_header('User-Agent', 'Mozilla/5.0')
                response = self.opener.open(req, timeout=5)
                body = response.read().decode('utf-8')
                # Check if we get a valid login page
                if 'password' in body.lower() or 'login' in body.lower():
                    return True
            except Exception:
                pass
            time_module.sleep(check_interval)

        return False

    def login(self):
        """Login to the AP and get session token"""
        req = urllib_request.Request(f"{self.base_url}/cgi-bin/luci")
        req.add_header('User-Agent', 'Mozilla/5.0')
        response = self.opener.open(req)
        login_html = response.read().decode('utf-8')

        # Detect if firmware uses SHA-512 (new) or MD5 (old)
        if 'sha512sum' in login_html:
            hashed_pw = self._hash_password_sha512(self.password)
        else:
            hashed_pw = self._hash_password_md5(self.password)

        login_data = f"username={self.username}&password={hashed_pw}&agree=1&account={self.username}"

        req = urllib_request.Request(f"{self.base_url}/cgi-bin/luci", data=to_bytes(login_data))
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'Mozilla/5.0')
        req.add_header('Referer', f'{self.base_url}/cgi-bin/luci')
        req.add_header('Origin', self.base_url)
        req.add_header('Cookie', 'is_login=1')

        response = self.opener.open(req)
        body = response.read().decode('utf-8')

        # Extract stok from response URL first (WAX210), then body (WAX218)
        final_url = response.geturl()
        stok_match = re.search(r'stok=([a-f0-9]+)', final_url)
        if not stok_match:
            # WAX218 puts stok in body, not URL
            stok_match = re.search(r'stok=([a-f0-9]+)', body)
        if not stok_match:
            return False

        self.stok = stok_match.group(1)

        for cookie in self.cookie_jar:
            if cookie.name == 'sysauth':
                self.sysauth = cookie.value
                break

        return True

    def get_csrf_token(self):
        """Get CSRF token from the device via AJAX endpoint"""
        if not self.stok:
            if not self.login():
                return None

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/system/ajax_getCsrf"
        body, _ = self._make_request(url)

        try:
            result = json.loads(body)
            return result.get('val_csrf')
        except Exception:
            return None

    def set_csrf_token(self):
        """Call ajax_setCsrf to prepare for form submission.

        The browser calls this before submitting a form.
        Returns the CSRF token if available.
        """
        if not self.stok:
            if not self.login():
                return None

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/system/ajax_setCsrf"
        body, _ = self._make_request(url)

        try:
            result = json.loads(body)
            return result.get('val_csrf')
        except Exception:
            return None

    def get_system_config(self):
        """Get current system configuration (AP name, management interface state)"""
        if not self.stok:
            if not self.login():
                return None

        # Get wireless_device page for AP name
        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        html, _ = self._make_request(url)

        config = {}

        # Extract AP Name
        ap_name_pattern = r'<input[^>]*id="cbid\.system\.system\.SystemName"[^>]*>'
        ap_name_tag = re.search(ap_name_pattern, html)
        if ap_name_tag:
            value_match = re.search(r'value="([^"]*)"', ap_name_tag.group(0))
            config['ap_name'] = value_match.group(1) if value_match else ''

        # Get interface status API for management interface state
        iface_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/iface_status2/99,mgmt"
        iface_body, _ = self._make_request(iface_url)

        try:
            ifaces = json.loads(iface_body)
            for iface in ifaces:
                if isinstance(iface, dict):
                    name = iface.get('name', '')
                    device = iface.get('device', '')
                    iwdata = iface.get('id', {})
                    if isinstance(iwdata, dict):
                        iwdata = iwdata.get('iwdata', {})
                    disabled = iwdata.get('disabled', '0') if isinstance(iwdata, dict) else '0'

                    # Management interfaces contain 'mgmt' in name or 'MGMT'/'CONFIG' in SSID
                    if 'mgmt' in name.lower() or 'EnMGMT' in name:
                        if device == 'wifi0':
                            config['mgmt_interface_2g'] = disabled != '1'
                        elif device == 'wifi1':
                            config['mgmt_interface_5g'] = disabled != '1'
        except (json.JSONDecodeError, TypeError):
            pass

        return config

    def _extract_form_fields(self, html):
        """Extract all form fields from an HTML page.

        Returns a dictionary of field name -> value for all inputs and selects.
        """
        form_data = {}

        # Find all input fields
        for match in re.finditer(r'<input[^>]*>', html, re.IGNORECASE):
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
        for match in re.finditer(r'<select[^>]*name="([^"]+)"[^>]*>(.*?)</select>', html, re.DOTALL | re.IGNORECASE):
            name = match.group(1)
            options = match.group(2)
            selected_match = re.search(r'<option[^>]*selected[^>]*value="([^"]*)"', options, re.IGNORECASE)
            if selected_match:
                form_data[name] = selected_match.group(1)

        return form_data

    def set_ap_name(self, new_name, wait_timeout=30):
        """Set AP name via wireless_device form submission.

        Uses two-step process:
        1. GET wireless_device page and extract ALL form fields
        2. Modify SystemName and POST complete form (staging)
        3. POST to saveapply (apply changes)
        4. Wait for device to be ready
        """
        if not self.stok:
            if not self.login():
                return False, "Login failed"

        # Step 0: Get the wireless_device page and extract all form fields
        page_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        try:
            body, _ = self._make_request(page_url)
        except Exception as e:
            return False, f"Could not get form page: {str(e)}"

        # Extract all form fields from the page
        form_data = self._extract_form_fields(body)
        if not form_data:
            return False, "Could not extract form fields from page"

        # Get CSRF token from AJAX endpoint (form has empty val_csrf)
        csrf_token = self.get_csrf_token()
        if not csrf_token:
            return False, "Could not obtain CSRF token"

        # Call set_csrf to prepare for form submission (browser does this)
        self.set_csrf_token()

        # Step 1: Modify the fields we want to change
        form_data['cbid.system.system.SystemName'] = new_name
        form_data['form_submit'] = '1'
        form_data['val_csrf'] = csrf_token

        # POST the complete form using direct request (like wireless module)
        submit_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        encoded_data = urllib_parse.urlencode(form_data).encode()

        req = urllib_request.Request(submit_url, data=encoded_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Referer', page_url)
        req.add_header('Origin', self.base_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        if self.sysauth:
            req.add_header('Cookie', f'sysauth={self.sysauth}')

        try:
            response = self.opener.open(req)
            response.read()  # consume response
        except urllib_error.HTTPError as e:
            return False, f"Form submission HTTP error: {e.code} - {e.reason}"
        except Exception as e:
            return False, f"Form submission error: {str(e)}"

        # Step 2: Apply changes using saveapply endpoint
        apply_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/uci/saveapply"
        apply_data = {
            'form_submit': '1',
            'val_csrf': csrf_token,
            'submitType': '2',
            'saveApply': '',
        }
        apply_encoded = urllib_parse.urlencode(apply_data).encode()

        req = urllib_request.Request(apply_url, data=apply_encoded, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Referer', submit_url)
        req.add_header('Origin', self.base_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        if self.sysauth:
            req.add_header('Cookie', f'sysauth={self.sysauth}')

        try:
            response = self.opener.open(req)
            response.read()  # consume response
        except urllib_error.HTTPError as e:
            return False, f"Apply HTTP error: {e.code} - {e.reason}"
        except Exception as e:
            return False, f"Apply error: {str(e)}"

        # Wait for device to be ready
        if not self.wait_for_ready(timeout=wait_timeout):
            return False, f"AP name set to {new_name} but device not responding after {wait_timeout}s"

        return True, f"AP name set to {new_name}"

    def set_mgmt_interface(self, wifi0_enabled=None, wifi1_enabled=None, wait_timeout=30):
        """Enable/disable management interface on radios.

        The management interface uses wifi0_mgmt (2.4GHz) and wifi1_mgmt (5GHz).
        Setting disabled=1 disables the interface, disabled=0 enables it.

        Uses complete form submission with all fields extracted from the page.
        """
        if not self.stok:
            if not self.login():
                return False, "Login failed"

        # Step 0: Get the wireless_device page and extract all form fields
        page_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        try:
            body, _ = self._make_request(page_url)
        except Exception as e:
            return False, f"Could not get form page: {str(e)}"

        # Extract all form fields from the page
        form_data = self._extract_form_fields(body)
        if not form_data:
            return False, "Could not extract form fields from page"

        # Get CSRF token - use val_csrf from form or fetch fresh one
        csrf_token = form_data.get('val_csrf') or self.get_csrf_token()
        if not csrf_token:
            return False, "Could not obtain CSRF token"

        # Call set_csrf to prepare for form submission (browser does this)
        self.set_csrf_token()

        # Step 1: Modify the fields we want to change
        form_data['form_submit'] = '1'
        form_data['val_csrf'] = csrf_token

        # Management interface disable checkboxes
        # Checkbox checked = disabled, unchecked = enabled
        if wifi0_enabled is not None:
            if not wifi0_enabled:
                form_data['cbid.wireless.wifi0_mgmt.disabled'] = '1'
            else:
                form_data['cbid.wireless.wifi0_mgmt.disabled'] = '0'

        if wifi1_enabled is not None:
            if not wifi1_enabled:
                form_data['cbid.wireless.wifi1_mgmt.disabled'] = '1'
            else:
                form_data['cbid.wireless.wifi1_mgmt.disabled'] = '0'

        # POST the complete form (staging)
        submit_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/network/wireless_device"
        self._make_request(submit_url, data=form_data, method='POST')

        # Step 2: Apply changes
        apply_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/uci/saveapply"
        apply_data = {
            'form_submit': '1',
            'val_csrf': csrf_token,
            'submitType': '2',
            'saveApply': '',
        }
        self._make_request(apply_url, data=apply_data, method='POST')

        # Wait for device to be ready
        changes = []
        if wifi0_enabled is not None:
            changes.append(f"2.4GHz={'enabled' if wifi0_enabled else 'disabled'}")
        if wifi1_enabled is not None:
            changes.append(f"5GHz={'enabled' if wifi1_enabled else 'disabled'}")

        if not self.wait_for_ready(timeout=wait_timeout):
            return False, f"Management interface set but device not responding after {wait_timeout}s"

        return True, f"Management interface: {', '.join(changes)}"


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            username=dict(type='str', required=False, default='admin'),
            password=dict(type='str', required=True, no_log=True),
            ap_name=dict(type='str', required=False),
            mgmt_interface_2g=dict(type='bool', required=False),
            mgmt_interface_5g=dict(type='bool', required=False),
            validate_certs=dict(type='bool', required=False, default=False),
        ),
        supports_check_mode=True
    )

    if not HAS_URLLIB:
        module.fail_json(msg="urllib is required for this module")

    api = WAX210SystemAPI(module)
    changed = False
    messages = []

    try:
        # Get current configuration
        current_config = api.get_system_config()
        if current_config is None:
            module.fail_json(msg="Failed to get current configuration - login may have failed")

        # Handle AP name change
        ap_name = module.params.get('ap_name')
        if ap_name is not None:
            if current_config.get('ap_name') != ap_name:
                if not module.check_mode:
                    success, msg = api.set_ap_name(ap_name)
                    if not success:
                        module.fail_json(msg=msg)
                    messages.append(msg)
                changed = True
            else:
                messages.append(f"AP name already set to {ap_name}")

        # Handle management interface changes
        mgmt_2g = module.params.get('mgmt_interface_2g')
        mgmt_5g = module.params.get('mgmt_interface_5g')

        mgmt_changed = False
        if mgmt_2g is not None and current_config.get('mgmt_interface_2g') != mgmt_2g:
            mgmt_changed = True
        if mgmt_5g is not None and current_config.get('mgmt_interface_5g') != mgmt_5g:
            mgmt_changed = True

        if mgmt_changed:
            if not module.check_mode:
                success, msg = api.set_mgmt_interface(
                    wifi0_enabled=mgmt_2g,
                    wifi1_enabled=mgmt_5g
                )
                if not success:
                    module.fail_json(msg=msg)
                messages.append(msg)
            changed = True
        else:
            if mgmt_2g is not None or mgmt_5g is not None:
                messages.append("Management interface already in desired state")

        # Get final config
        final_config = api.get_system_config() if changed and not module.check_mode else current_config

        module.exit_json(
            changed=changed,
            message="; ".join(messages) if messages else "No changes required",
            config=final_config
        )

    except urllib_error.URLError as e:
        module.fail_json(msg=f"HTTP request failed: {str(e)}")
    except Exception as e:
        module.fail_json(msg=f"Unexpected error: {str(e)}")


if __name__ == '__main__':
    main()
