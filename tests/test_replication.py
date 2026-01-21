#!/usr/bin/env python3
"""Test replication from source AP (.10) to target AP (.16) - ALL MODULES

Usage:
    python3 tests/test_replication.py              # Run all tests
    python3 tests/test_replication.py system       # Run only system test
    python3 tests/test_replication.py radio        # Run only radio test
    python3 tests/test_replication.py wireless     # Run only wireless test
    python3 tests/test_replication.py system radio # Run system and radio tests
"""
import argparse
import os
import sys
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, 'plugins/modules')

from netgear_wax_system import WAX210SystemAPI
from netgear_wax_wireless import WAX210API as WAX210WirelessAPI
from netgear_wax_radio import WAX210RadioAPI


class FakeModule:
    def __init__(self, host, password):
        self.params = {'host': host, 'password': password, 'username': 'admin'}


def test_system_module(source, target, password):
    """Test system module - AP name replication"""
    print("\n" + "=" * 60)
    print("TEST 1: SYSTEM MODULE (AP Name)")
    print("=" * 60)

    # Read source
    src = WAX210SystemAPI(FakeModule(source, password))
    if not src.login():
        return False, "Could not login to source"
    src_config = src.get_system_config()
    src_ap_name = src_config.get('ap_name', 'UNKNOWN')
    print(f"  Source AP Name: {src_ap_name}")

    # Read target before
    tgt = WAX210SystemAPI(FakeModule(target, password))
    if not tgt.login():
        return False, "Could not login to target"
    tgt_config = tgt.get_system_config()
    print(f"  Target AP Name (before): {tgt_config.get('ap_name', 'UNKNOWN')}")

    # Apply
    print(f"  Setting target AP name to: {src_ap_name}")
    success, msg = tgt.set_ap_name(src_ap_name)
    if not success:
        return False, f"set_ap_name failed: {msg}"

    # Verify
    tgt2 = WAX210SystemAPI(FakeModule(target, password))
    if not tgt2.login():
        return False, "Could not login to target for verification"
    tgt_config2 = tgt2.get_system_config()
    new_name = tgt_config2.get('ap_name', 'UNKNOWN')
    print(f"  Target AP Name (after): {new_name}")

    if new_name == src_ap_name:
        return True, "AP name replicated"
    return False, f"Mismatch: expected '{src_ap_name}', got '{new_name}'"


def test_radio_module(source, target, password):
    """Test radio module - channel replication"""
    print("\n" + "=" * 60)
    print("TEST 2: RADIO MODULE (Channels)")
    print("=" * 60)

    # Read source
    src = WAX210RadioAPI(FakeModule(source, password))
    if not src.login():
        return False, "Could not login to source"
    src_config = src.get_radio_config()
    src_ch0 = src_config.get('wifi0_channel', 'auto')
    src_ch1 = src_config.get('wifi1_channel', '36')
    print(f"  Source 2.4GHz: {src_ch0}, 5GHz: {src_ch1}")

    # Read target before
    tgt = WAX210RadioAPI(FakeModule(target, password))
    if not tgt.login():
        return False, "Could not login to target"
    tgt_config = tgt.get_radio_config()
    print(f"  Target (before) 2.4GHz: {tgt_config.get('wifi0_channel')}, 5GHz: {tgt_config.get('wifi1_channel')}")

    # Apply
    print(f"  Setting target channels to: 2.4GHz={src_ch0}, 5GHz={src_ch1}")
    success, msg = tgt.set_channels(channel_2g=src_ch0, channel_5g=src_ch1)
    if not success:
        return False, f"set_channels failed: {msg}"

    # Verify
    tgt2 = WAX210RadioAPI(FakeModule(target, password))
    if not tgt2.login():
        return False, "Could not login to target for verification"
    tgt_config2 = tgt2.get_radio_config()
    new_ch0 = tgt_config2.get('wifi0_channel', 'UNKNOWN')
    new_ch1 = tgt_config2.get('wifi1_channel', 'UNKNOWN')
    print(f"  Target (after) 2.4GHz: {new_ch0}, 5GHz: {new_ch1}")

    if new_ch0 == src_ch0 and new_ch1 == src_ch1:
        return True, "Channels replicated"
    return False, f"Mismatch: expected {src_ch0}/{src_ch1}, got {new_ch0}/{new_ch1}"


def test_wireless_module(source, target, password, ssid_name='JTW'):
    """Test wireless module - SSID config replication"""
    print("\n" + "=" * 60)
    print(f"TEST 3: WIRELESS MODULE (SSID: {ssid_name})")
    print("=" * 60)

    # Read source
    src = WAX210WirelessAPI(FakeModule(source, password))
    if not src.login():
        return False, "Could not login to source"

    # Get wireless config and list SSIDs
    src_config = src.get_wireless_config()
    src_ssids = [iface.get('name') for iface in src_config if isinstance(iface, dict) and iface.get('name')]
    print(f"  Source SSIDs: {src_ssids}")

    if ssid_name not in src_ssids:
        return False, f"SSID '{ssid_name}' not found on source"

    # Get slot for this SSID
    src_slot = src.get_ssid_slot(ssid_name)
    if not src_slot:
        return False, f"Could not find slot for '{ssid_name}'"
    print(f"  Source {ssid_name} slot: {src_slot}")

    # Get SSID config via popup
    src_ssid_config = src.get_ssid_config_via_popup(src_slot)
    if not src_ssid_config:
        return False, f"Could not get config for '{ssid_name}'"
    print(f"  Source {ssid_name} VLAN: {src_ssid_config.get('vlan', 'UNKNOWN')}")

    # Read target
    tgt = WAX210WirelessAPI(FakeModule(target, password))
    if not tgt.login():
        return False, "Could not login to target"

    tgt_config = tgt.get_wireless_config()
    tgt_ssids = [iface.get('name') for iface in tgt_config if isinstance(iface, dict) and iface.get('name')]
    print(f"  Target SSIDs: {tgt_ssids}")

    if ssid_name not in tgt_ssids:
        return False, f"SSID '{ssid_name}' not found on target"

    tgt_slot = tgt.get_ssid_slot(ssid_name)
    if not tgt_slot:
        return False, f"Could not find slot for '{ssid_name}' on target"

    tgt_ssid_config = tgt.get_ssid_config_via_popup(tgt_slot)
    print(f"  Target {ssid_name} VLAN (before): {tgt_ssid_config.get('vlan', 'UNKNOWN')}")

    # Apply - replicate VLAN
    src_vlan = src_ssid_config.get('vlan', 'vlan1')
    print(f"  Setting target {ssid_name} VLAN to: {src_vlan}")
    success, msg = tgt.set_ssid_vlan_via_popup(tgt_slot, src_vlan)
    if not success:
        return False, f"set_ssid_vlan failed: {msg}"

    # Verify
    tgt2 = WAX210WirelessAPI(FakeModule(target, password))
    if not tgt2.login():
        return False, "Could not login to target for verification"
    tgt2_ssid_config = tgt2.get_ssid_config_via_popup(tgt_slot)
    new_vlan = tgt2_ssid_config.get('vlan', 'UNKNOWN')
    print(f"  Target {ssid_name} VLAN (after): {new_vlan}")

    if new_vlan == src_vlan:
        return True, f"SSID {ssid_name} VLAN replicated"
    return False, f"Mismatch: expected '{src_vlan}', got '{new_vlan}'"


def main():
    parser = argparse.ArgumentParser(description='Test replication between WAX devices')
    parser.add_argument('tests', nargs='*', default=['all'],
                        choices=['all', 'system', 'radio', 'wireless'],
                        help='Which tests to run (default: all)')
    args = parser.parse_args()

    # Determine which tests to run
    run_all = 'all' in args.tests
    run_system = run_all or 'system' in args.tests
    run_radio = run_all or 'radio' in args.tests
    run_wireless = run_all or 'wireless' in args.tests

    SOURCE = os.environ.get('SOURCE_HOST', '172.19.4.10')
    TARGET = os.environ.get('TARGET_HOST', '172.19.4.16')
    PASSWORD = os.environ.get('WAX_PASSWORD', '')
    SSID = os.environ.get('TEST_SSID', 'JTW')

    if not PASSWORD:
        print("ERROR: WAX_PASSWORD environment variable not set")
        sys.exit(1)

    tests_to_run = [t for t in args.tests if t != 'all'] or ['system', 'radio', 'wireless']
    print("=" * 60)
    print(f"REPLICATION TEST: {SOURCE} -> {TARGET}")
    print(f"Running: {', '.join(tests_to_run)}")
    print("=" * 60)

    results = []

    # Test 1: System module
    if run_system:
        success, msg = test_system_module(SOURCE, TARGET, PASSWORD)
        results.append(('System (AP Name)', success, msg))
        print(f"  {'✅' if success else '❌'} {msg}")

    # Test 2: Radio module
    if run_radio:
        success, msg = test_radio_module(SOURCE, TARGET, PASSWORD)
        results.append(('Radio (Channels)', success, msg))
        print(f"  {'✅' if success else '❌'} {msg}")

    # Test 3: Wireless module
    if run_wireless:
        success, msg = test_wireless_module(SOURCE, TARGET, PASSWORD, SSID)
        results.append(('Wireless (SSID)', success, msg))
        print(f"  {'✅' if success else '❌'} {msg}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, s, _ in results if s)
    total = len(results)
    for name, success, msg in results:
        print(f"  {'✅' if success else '❌'} {name}: {msg}")
    print(f"\n  {passed}/{total} tests passed")

    if passed == total:
        print("\n✅ ALL TESTS PASSED!")
    else:
        print("\n❌ SOME TESTS FAILED!")
        sys.exit(1)

    print("=" * 60)


if __name__ == '__main__':
    main()

