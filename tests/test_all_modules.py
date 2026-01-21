#!/usr/bin/env python3
"""Test all modules on both WAX210 and WAX218 devices.

Usage:
    WAX_PASSWORD=yourpassword python3 tests/test_all_modules.py
"""
import os
import sys
sys.path.insert(0, 'plugins/modules')

DEVICES = [
    ('WAX210', '172.19.4.10'),
    ('WAX218', '172.19.4.14'),
    ('WAX210-2', '172.19.4.16'),
]
PASSWORD = os.environ.get('WAX_PASSWORD')
if not PASSWORD:
    print("ERROR: Set WAX_PASSWORD environment variable")
    print("Usage: WAX_PASSWORD=yourpassword python3 tests/test_all_modules.py")
    sys.exit(1)

class FakeModule:
    def __init__(self):
        self.params = {}
    def fail_json(self, **kwargs):
        raise Exception(kwargs.get('msg', str(kwargs)))

def test_info():
    """Test netgear_wax_info module."""
    print("=" * 60)
    print("TEST 1: netgear_wax_info (read config)")
    print("=" * 60)
    from netgear_wax_info import WAXInfoAPI
    results = []
    for name, host in DEVICES:
        try:
            module = FakeModule()
            module.params = {'host': host, 'username': 'admin', 'password': PASSWORD, 'validate_certs': False}
            api = WAXInfoAPI(module)
            if api.login():
                config = api.get_wireless_config()
                print(f"  ✅ {name}: Got {len(config)} interfaces")
                results.append((name, True))
            else:
                print(f"  ❌ {name}: Login failed")
                results.append((name, False))
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            results.append((name, False))
    return results

def test_radio():
    """Test netgear_wax_radio module."""
    print("\n" + "=" * 60)
    print("TEST 2: netgear_wax_radio (read channels)")
    print("=" * 60)
    from netgear_wax_radio import WAX210RadioAPI
    results = []
    for name, host in DEVICES:
        try:
            module = FakeModule()
            module.params = {'host': host, 'username': 'admin', 'password': PASSWORD, 'validate_certs': False}
            api = WAX210RadioAPI(module)
            if api.login():
                config = api.get_radio_config()
                print(f"  ✅ {name}: wifi0={config.get('wifi0_channel')}, wifi1={config.get('wifi1_channel')}")
                results.append((name, True))
            else:
                print(f"  ❌ {name}: Login failed")
                results.append((name, False))
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            results.append((name, False))
    return results

def test_system():
    """Test netgear_wax_system module."""
    print("\n" + "=" * 60)
    print("TEST 3: netgear_wax_system (read AP name)")
    print("=" * 60)
    from netgear_wax_system import WAX210SystemAPI
    results = []
    for name, host in DEVICES:
        try:
            module = FakeModule()
            module.params = {'host': host, 'username': 'admin', 'password': PASSWORD, 'validate_certs': False}
            api = WAX210SystemAPI(module)
            if api.login():
                config = api.get_system_config()
                print(f"  ✅ {name}: AP Name = {config.get('ap_name', 'unknown')}")
                results.append((name, True))
            else:
                print(f"  ❌ {name}: Login failed")
                results.append((name, False))
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            results.append((name, False))
    return results

def test_wireless():
    """Test netgear_wax_wireless module."""
    print("\n" + "=" * 60)
    print("TEST 4: netgear_wax_wireless (read SSID config)")
    print("=" * 60)
    from netgear_wax_wireless import WAX210API
    results = []
    for name, host in DEVICES:
        try:
            module = FakeModule()
            module.params = {'host': host, 'username': 'admin', 'password': PASSWORD, 
                           'validate_certs': False, 'model': None}
            api = WAX210API(module)
            if api.login():
                ssids = api.find_ssid_config('VOV')
                print(f"  ✅ {name}: Model={api.model}, Endpoint={api.ssid_popup_endpoint.split('/')[-1]}")
                results.append((name, True))
            else:
                print(f"  ❌ {name}: Login failed")
                results.append((name, False))
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            results.append((name, False))
    return results

if __name__ == '__main__':
    all_results = []
    all_results.extend(test_info())
    all_results.extend(test_radio())
    all_results.extend(test_system())
    all_results.extend(test_wireless())
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, ok in all_results if ok)
    total = len(all_results)
    print(f"  {passed}/{total} tests passed")
    
    if passed == total:
        print("  ✅ All tests passed!")
        sys.exit(0)
    else:
        print("  ❌ Some tests failed")
        sys.exit(1)

