#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Ansible Netgear WAP Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Base API class for NETGEAR WAX series wireless access points.

Provides shared functionality for all WAX modules:
- Login (SHA-512/MD5 auto-detection, stok extraction)
- CSRF token handling (get_csrf_token, set_csrf_token)
- HTTP request methods with proper headers
- Model detection
- Session management
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import hashlib
import re
import ssl
import time
import http.cookiejar

try:
    import urllib.request as urllib_request
    import urllib.error as urllib_error
    import urllib.parse as urllib_parse
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from ansible.module_utils._text import to_bytes


class WAXBaseAPI:
    """Base API client for NETGEAR WAX series access points.
    
    Handles authentication, session management, and common HTTP operations.
    Supports both WAX210 (SHA-512 auth) and WAX218 (MD5 auth) models.
    """

    def __init__(self, module):
        """Initialize the API client.
        
        Args:
            module: AnsibleModule instance with params (host, username, password, validate_certs)
        """
        self.module = module
        self.host = module.params['host']
        self.username = module.params.get('username', 'admin')
        self.password = module.params['password']
        self.validate_certs = module.params.get('validate_certs', False)
        self.base_url = None
        self.stok = None
        self.sysauth = None
        self.model = None
        self.opener = None
        self.cookie_jar = None
        self._setup_opener()
        self._detect_protocol()

    def _setup_opener(self):
        """Setup urllib opener with SSL context and cookies"""
        ctx = ssl.create_default_context()
        if not self.validate_certs:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib_request.build_opener(
            urllib_request.HTTPCookieProcessor(self.cookie_jar),
            urllib_request.HTTPSHandler(context=ctx)
        )

    def _detect_protocol(self):
        """Auto-detect whether to use HTTP or HTTPS"""
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
        self.base_url = f"https://{self.host}"

    def _hash_password_sha512(self, password):
        """Hash password using SHA512 (newer firmware, WAX210)"""
        return hashlib.sha512(to_bytes(password + "\n")).hexdigest()

    def _hash_password_md5(self, password):
        """Hash password using MD5 (older firmware, WAX218)"""
        return hashlib.md5(to_bytes(password + "\n")).hexdigest()

    def _get_headers(self):
        """Get standard request headers"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0',
            'Referer': f'{self.base_url}/cgi-bin/luci',
            'Origin': self.base_url
        }
        return headers

    def _make_request(self, url, data=None, method='GET'):
        """Make HTTP request and return response body.
        
        Args:
            url: Full URL to request
            data: Dict of form data (will be URL-encoded) or None
            method: HTTP method (GET, POST)
            
        Returns:
            tuple: (body_string, response_object)
            
        Raises:
            Calls module.fail_json on HTTP errors
        """
        if data and isinstance(data, dict):
            encoded_data = urllib_parse.urlencode(data).encode()
            req = urllib_request.Request(url, data=encoded_data, method=method)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        elif data and isinstance(data, str):
            req = urllib_request.Request(url, data=to_bytes(data), method=method)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        else:
            req = urllib_request.Request(url, method=method)

        for key, val in self._get_headers().items():
            req.add_header(key, val)
        
        if self.sysauth:
            req.add_header('Cookie', f'sysauth={self.sysauth}; is_login=1')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
            return body, response
        except urllib_error.HTTPError as e:
            return None, e
        except urllib_error.URLError as e:
            self.module.fail_json(msg=f"URL error: {e.reason}")

    def login(self):
        """Login to the AP and get session token.

        Auto-detects firmware type (SHA-512 vs MD5) and model.
        Extracts stok from URL (WAX210) or body (WAX218).

        Returns:
            bool: True if login successful, False otherwise
        """
        login_url = f"{self.base_url}/cgi-bin/luci"

        # Get login page to detect firmware/model
        req = urllib_request.Request(login_url)
        req.add_header('User-Agent', 'Mozilla/5.0')

        try:
            response = self.opener.open(req)
            login_html = response.read().decode('utf-8')
        except Exception as e:
            self.module.fail_json(msg=f"Failed to access login page: {str(e)}")
            return False

        # Auto-detect model from login page
        if not self.model:
            model_match = re.search(r'(WAX\d+)', login_html)
            self.model = model_match.group(1) if model_match else 'WAX210'

        # Detect if firmware uses SHA-512 (new) or MD5 (old)
        if 'sha512sum' in login_html:
            hashed_pw = self._hash_password_sha512(self.password)
        else:
            hashed_pw = self._hash_password_md5(self.password)

        # Submit login
        login_data = f"username={self.username}&password={hashed_pw}&agree=1&account={self.username}"

        req = urllib_request.Request(login_url, data=to_bytes(login_data))
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'Mozilla/5.0')
        req.add_header('Referer', f'{self.base_url}/cgi-bin/luci')
        req.add_header('Origin', self.base_url)
        req.add_header('Cookie', 'is_login=1')

        try:
            response = self.opener.open(req)
            body = response.read().decode('utf-8')
        except Exception as e:
            self.module.fail_json(msg=f"Login request failed: {str(e)}")
            return False

        # Extract stok from URL (WAX210) or body (WAX218)
        final_url = response.geturl()
        stok_match = re.search(r'stok=([a-f0-9]+)', final_url)
        if not stok_match:
            stok_match = re.search(r'stok=([a-f0-9]+)', body)

        if not stok_match:
            return False

        self.stok = stok_match.group(1)

        # Extract sysauth cookie
        for cookie in self.cookie_jar:
            if cookie.name == 'sysauth':
                self.sysauth = cookie.value
                break

        return True

    def get_sysauth_cookie(self):
        """Get the sysauth cookie value from the cookie jar"""
        for cookie in self.cookie_jar:
            if cookie.name == 'sysauth':
                return cookie.value
        return None

    def get_csrf_token(self):
        """Get CSRF token from the device via AJAX endpoint.

        Returns:
            str: CSRF token value, or None if failed
        """
        if not self.stok:
            if not self.login():
                return None

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/system/ajax_getCsrf"
        body, response = self._make_request(url)

        if body is None:
            return None

        try:
            result = json.loads(body)
            return result.get('val_csrf', '')
        except Exception:
            return ''

    def set_csrf_token(self):
        """Call ajax_setCsrf to prepare for form submission.

        The browser calls this before submitting a form.
        This is REQUIRED before any POST operation.

        Returns:
            str: CSRF token value if available, None otherwise
        """
        if not self.stok:
            if not self.login():
                return None

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/system/ajax_setCsrf"
        body, response = self._make_request(url)

        if body is None:
            return None

        try:
            result = json.loads(body)
            return result.get('val_csrf')
        except Exception:
            return None

    def wait_for_ready(self, timeout=30, check_interval=2):
        """Wait for device to be ready after applying changes.

        Polls the login page until responsive or timeout.

        Args:
            timeout: Maximum seconds to wait
            check_interval: Seconds between checks

        Returns:
            bool: True if device is ready, False if timeout
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                req = urllib_request.Request(f"{self.base_url}/cgi-bin/luci")
                req.add_header('User-Agent', 'Mozilla/5.0')
                response = self.opener.open(req, timeout=5)
                body = response.read().decode('utf-8')
                if 'password' in body.lower() or 'login' in body.lower():
                    return True
            except Exception:
                pass
            time.sleep(check_interval)

        return False

    def apply_changes(self):
        """Apply staged UCI changes via saveapply endpoint.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.stok:
            if not self.login():
                return False

        save_url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/admin/uci/saveapply"
        body, response = self._make_request(save_url)

        return body is not None

