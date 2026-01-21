#!/usr/bin/env python3
"""Test setting AP name with the fixed system module."""

import sys
import os
sys.path.insert(0, 'plugins/modules')

from netgear_wax_system import WAX210SystemAPI


class FakeModule:
    def __init__(self, host, password):
        self.params = {
            'host': host,
            'password': password,
            'username': 'admin'
        }


def main():
    host = os.environ.get('WAX_HOST', '172.19.4.16')
    password = os.environ.get('WAX_PASSWORD')
    
    if not password:
        print("Error: WAX_PASSWORD environment variable not set")
        sys.exit(1)
    
    new_name = os.environ.get('AP_NAME', 'wap-gen2')
    
    module = FakeModule(host, password)
    api = WAX210SystemAPI(module)
    
    print(f"Testing AP name change on {host}...")
    print(f"Target AP name: {new_name}")
    print()
    
    print("Step 1: Logging in...")
    if not api.login():
        print("ERROR: Login failed")
        sys.exit(1)
    print(f"  Logged in. stok={api.stok[:16]}...")
    
    print("Step 2: Getting current config...")
    config = api.get_system_config()
    old_name = config.get('ap_name', 'UNKNOWN')
    print(f"  Current AP name: {old_name}")
    
    if old_name == new_name:
        print(f"  AP name is already '{new_name}'")
        print("SUCCESS: No change needed")
        sys.exit(0)
    
    print(f"Step 3: Setting AP name to '{new_name}'...")
    success, msg = api.set_ap_name(new_name)
    print(f"  Result: success={success}, msg={msg}")
    
    if not success:
        print("ERROR: Failed to set AP name")
        sys.exit(1)
    
    print("Step 4: Verifying change (re-login)...")
    api2 = WAX210SystemAPI(module)
    if not api2.login():
        print("ERROR: Could not re-login to verify")
        sys.exit(1)
    
    config2 = api2.get_system_config()
    new_name_actual = config2.get('ap_name', 'UNKNOWN')
    print(f"  New AP name: {new_name_actual}")
    
    if new_name_actual == new_name:
        print()
        print("=" * 40)
        print("SUCCESS: AP name changed successfully!")
        print(f"  Before: {old_name}")
        print(f"  After:  {new_name_actual}")
        print("=" * 40)
        sys.exit(0)
    else:
        print()
        print("=" * 40)
        print("FAILED: AP name did not change")
        print(f"  Expected: {new_name}")
        print(f"  Actual:   {new_name_actual}")
        print("=" * 40)
        sys.exit(1)


if __name__ == '__main__':
    main()

