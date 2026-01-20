#!/usr/bin/env python3
"""
Automated Luci Interface Analyzer for NETGEAR WAX Series Access Points

Uses Selenium + MITM proxy to automatically probe and analyze the LuCI web interface.
Handles popup windows, Save/Apply workflow, and captures all traffic.

USAGE:
    python3 automated_luci_analyzer.py --host 172.19.4.10 --password <password>

REQUIREMENTS:
    - Firefox browser
    - geckodriver (brew install geckodriver on macOS)
    - mitmproxy (pip install mitmproxy)
    - selenium (pip install selenium)

WHAT THIS TOOL DISCOVERS:
    - Form field names and values (cbid.* UCI format)
    - API endpoints and their parameters
    - Popup form URLs and submission patterns
    - CSRF token handling
    - Session token (stok) management

KEY FINDINGS FOR WAX210 (V1.1.0.34):
    - Authentication: SHA-512 hash of password + newline
    - Session: stok token in URL path, sysauth cookie
    - SSID Config: /admin/network/wifi_Encryption_P2P popup form
    - Channel Config: /admin/network/wifi_Channel popup form
    - System Config: /admin/network/wireless_device main page
    - Passphrase: AES-256-ECB encrypted with static key

OUTPUT:
    Creates timestamped directory with:
    - HTML page captures at each stage
    - PNG screenshots
    - JSON files with form field data
    - MITM proxy logs of all HTTP traffic
"""

import json
import time
import subprocess
import signal
import sys
from pathlib import Path
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.common.exceptions import TimeoutException, NoSuchWindowException

class LuciAnalyzer:
    def __init__(self, host, username, password, proxy_port=8888):
        self.host = host
        self.username = username
        self.password = password
        self.proxy_port = proxy_port
        self.driver = None
        self.mitm_process = None
        self.main_window = None
        self.session_dir = None
        
    def start_mitm_proxy(self):
        """Start mitmproxy in background"""
        print(f"\n{'='*60}")
        print("🚀 Starting MITM Proxy")
        print(f"{'='*60}")
        
        cmd = [
            'mitmdump',
            '-s', 'luci_capture_addon.py',
            '--listen-port', str(self.proxy_port),
            '--ssl-insecure',
            '--set', 'stream_large_bodies=1'
        ]
        
        self.mitm_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        print(f"✅ MITM proxy started on port {self.proxy_port}")
        print("   Waiting for proxy to initialize...")
        time.sleep(3)
        
    def stop_mitm_proxy(self):
        """Stop mitmproxy"""
        if self.mitm_process:
            print("\n🛑 Stopping MITM proxy...")
            self.mitm_process.send_signal(signal.SIGINT)
            self.mitm_process.wait(timeout=5)
            print("✅ MITM proxy stopped")
    
    def start_browser(self):
        """Start Firefox with proxy configuration"""
        print(f"\n{'='*60}")
        print("🌐 Starting Firefox with Proxy")
        print(f"{'='*60}")
        
        # Configure Firefox options
        options = Options()
        options.accept_insecure_certs = True
        
        # Set proxy
        options.set_preference("network.proxy.type", 1)
        options.set_preference("network.proxy.http", "127.0.0.1")
        options.set_preference("network.proxy.http_port", self.proxy_port)
        options.set_preference("network.proxy.ssl", "127.0.0.1")
        options.set_preference("network.proxy.ssl_port", self.proxy_port)
        options.set_preference("network.proxy.no_proxies_on", "")
        
        # Disable popup blocking
        options.set_preference("dom.disable_open_during_load", False)
        options.set_preference("dom.popup_maximum", 100)
        
        # Start browser
        self.driver = webdriver.Firefox(options=options)
        self.driver.set_page_load_timeout(30)
        
        print("✅ Firefox started with proxy configuration")
        
    def login(self):
        """Login to the Luci interface"""
        print(f"\n{'='*60}")
        print(f"🔐 Logging in to {self.host}")
        print(f"{'='*60}")

        url = f"https://{self.host}/cgi-bin/luci"
        self.driver.get(url)

        # Store main window handle
        self.main_window = self.driver.current_window_handle

        # Wait for login page
        time.sleep(3)

        # Save screenshot for debugging
        try:
            self.driver.save_screenshot("login_page_before.png")
            print("   Saved screenshot: login_page_before.png")
        except:
            pass

        # Find and fill login form using JavaScript
        # The WAX210 login uses:
        # - 'account' field for visible username (copies to hidden 'username')
        # - 'password_plain_text' for visible password (gets SHA512 hashed to hidden 'password')
        # - 'agree_info' checkbox must be checked
        # - saveChanges() function handles submission
        try:
            # Use JavaScript to fill form and call saveChanges()
            login_script = f"""
            // Set visible username field
            var accountField = document.getElementById('account');
            if (accountField) {{
                accountField.value = '{self.username}';
            }}

            // Set visible password field
            var pwField = document.getElementById('password_plain_text');
            if (pwField) {{
                pwField.value = '{self.password}';
            }}

            // Check the agreement checkbox if it exists
            var agreeBox = document.getElementById('agree_info');
            if (agreeBox) {{
                agreeBox.checked = true;
            }}

            // Call the saveChanges function which handles SHA512 hashing and form submission
            if (typeof saveChanges === 'function') {{
                saveChanges();
                return 'called_saveChanges';
            }}

            // Fallback: manually hash and submit
            var f = document.formname;
            if (f && f.password_plain_text && f.password && f.username) {{
                // This requires the sha512sum function to be available
                if (typeof sha512sum === 'function') {{
                    f.password.value = sha512sum(f.password_plain_text.value + "\\n");
                    f.username.value = f.account.value;
                    f.submit();
                    return 'manual_submit_with_hash';
                }}
            }}

            return 'failed';
            """

            result = self.driver.execute_script(login_script)
            print(f"   Login action: {result}")

            if result == 'failed':
                print("❌ Login form handling failed")
                return False

            # Wait for redirect
            time.sleep(5)

            # Save screenshot after login attempt
            try:
                self.driver.save_screenshot("login_page_after.png")
                print("   Saved screenshot: login_page_after.png")
            except:
                pass

            # Check if logged in (look for stok in URL)
            current_url = self.driver.current_url
            print(f"   Current URL: {current_url}")

            if 'stok=' in current_url:
                print("✅ Login successful")
                return True
            else:
                print("❌ Login failed - no stok in URL")
                # Save page source for debugging
                with open("login_page_source.html", "w") as f:
                    f.write(self.driver.page_source)
                print("   Saved page source: login_page_source.html")
                return False

        except Exception as e:
            print(f"❌ Login error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def navigate_to_wireless(self):
        """Navigate to wireless configuration page"""
        print(f"\n{'='*60}")
        print("📡 Navigating to Wireless Configuration")
        print(f"{'='*60}")
        
        # Use JavaScript to navigate
        self.driver.execute_script("""
            window.location.href = window.location.href.replace(/admin\\/.*/, 'admin/network/wireless_device');
        """)
        
        time.sleep(3)
        print("✅ On wireless configuration page")
        
    def get_all_form_fields(self):
        """Extract all form fields from current page"""
        print(f"\n{'='*60}")
        print("📋 Extracting Form Fields")
        print(f"{'='*60}")
        
        script = """
        var fields = {};
        var inputs = document.querySelectorAll('input, select, textarea');
        inputs.forEach(function(input) {
            var name = input.name || input.id;
            if (name) {
                var value = input.type === 'checkbox' ? input.checked : input.value;
                fields[name] = {
                    type: input.type || input.tagName.toLowerCase(),
                    value: value,
                    id: input.id,
                    name: input.name
                };
            }
        });
        return fields;
        """
        
        fields = self.driver.execute_script(script)
        print(f"✅ Found {len(fields)} form fields")
        
        return fields
    
    def find_and_handle_popups(self):
        """Find Edit buttons and handle popup windows"""
        print(f"\n{'='*60}")
        print("🪟 Checking for Popup Windows")
        print(f"{'='*60}")
        
        # Get all window handles
        all_windows = self.driver.window_handles
        
        if len(all_windows) > 1:
            print(f"✅ Found {len(all_windows)-1} popup window(s)")
            
            for window in all_windows:
                if window != self.main_window:
                    self.driver.switch_to.window(window)
                    print(f"   Popup URL: {self.driver.current_url}")
                    
                    # Extract fields from popup
                    popup_fields = self.get_all_form_fields()
                    
                    # Save popup fields
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"popup_fields_{timestamp}.json"
                    with open(filename, 'w') as f:
                        json.dump(popup_fields, f, indent=2)
                    print(f"   Saved popup fields to {filename}")
            
            # Switch back to main window
            self.driver.switch_to.window(self.main_window)
            print("   Switched back to main window")
        else:
            print("   No popup windows found")

    def click_edit_buttons(self):
        """Find and click all Edit buttons in SSID table to open config subpages"""
        print(f"\n{'='*60}")
        print("🖱️  Finding Edit Buttons in SSID Table")
        print(f"{'='*60}")

        # Find all Edit buttons - they can be input[type=button], button, or styled links
        script = """
        var buttons = [];
        // Look for inputs with value="Edit"
        document.querySelectorAll('input[type="button"][value="Edit"], input[type="submit"][value="Edit"]').forEach(function(btn, idx) {
            // Try to find the SSID name in the same row
            var row = btn.closest('tr');
            var ssidName = '';
            if (row) {
                var ssidCell = row.querySelector('input[type="text"]');
                if (ssidCell) ssidName = ssidCell.value;
            }
            buttons.push({
                index: idx,
                ssidName: ssidName,
                tagName: btn.tagName,
                id: btn.id || '',
                name: btn.name || '',
                className: btn.className || ''
            });
        });
        // Also look for button elements with Edit text
        document.querySelectorAll('button').forEach(function(btn, idx) {
            if (btn.textContent.trim() === 'Edit') {
                var row = btn.closest('tr');
                var ssidName = '';
                if (row) {
                    var ssidCell = row.querySelector('input[type="text"]');
                    if (ssidCell) ssidName = ssidCell.value;
                }
                buttons.push({
                    index: idx + 100,
                    ssidName: ssidName,
                    tagName: btn.tagName,
                    id: btn.id || '',
                    name: btn.name || '',
                    className: btn.className || ''
                });
            }
        });
        return buttons;
        """

        edit_buttons = self.driver.execute_script(script)
        print(f"✅ Found {len(edit_buttons)} Edit button(s)")

        for btn in edit_buttons:
            ssid_info = f" (SSID: {btn['ssidName']})" if btn['ssidName'] else ""
            print(f"   - {btn['tagName']} id='{btn['id']}' name='{btn['name']}'{ssid_info}")

        # Store edit button info for later use
        self.edit_buttons = edit_buttons

        # Click each Edit button and capture the subpage
        for i, btn_info in enumerate(edit_buttons):
            ssid_name = btn_info.get('ssidName', f'ssid_{i}')
            print(f"\n   📝 Clicking Edit for: {ssid_name or f'Button {i+1}'}")

            # Click the button
            click_script = f"""
            var buttons = document.querySelectorAll('input[type="button"][value="Edit"], input[type="submit"][value="Edit"], button');
            var editBtns = [];
            buttons.forEach(function(btn) {{
                if (btn.value === 'Edit' || btn.textContent.trim() === 'Edit') {{
                    editBtns.push(btn);
                }}
            }});
            if (editBtns[{i}]) {{
                editBtns[{i}].click();
                return true;
            }}
            return false;
            """

            clicked = self.driver.execute_script(click_script)
            if clicked:
                time.sleep(2)  # Wait for popup window to open

                # Check if a new window opened
                window_handles = self.driver.window_handles
                if len(window_handles) > 1:
                    print(f"      🪟 Popup window detected ({len(window_handles)} windows)")

                    # Switch to the new popup window
                    main_window = window_handles[0]
                    popup_window = window_handles[-1]
                    self.driver.switch_to.window(popup_window)

                    time.sleep(1)  # Wait for popup content to load

                    current_url = self.driver.current_url
                    print(f"      Popup URL: {current_url}")

                    # Capture the popup page state
                    safe_name = ssid_name.replace(' ', '_').replace('/', '_') if ssid_name else f'ssid_{i}'
                    self.capture_page_state(f"ssid_popup_{safe_name}")

                    # Extract form fields from popup
                    popup_fields = self.get_all_form_fields()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"ssid_popup_{safe_name}_{timestamp}_fields.json"
                    with open(filename, 'w') as f:
                        json.dump(popup_fields, f, indent=2)
                    print(f"      Saved {len(popup_fields)} popup fields to {filename}")

                    # Look for VLAN/isolation fields specifically
                    vlan_fields = {k: v for k, v in popup_fields.items()
                                  if 'vlan' in k.lower() or 'isolation' in k.lower() or 'vid' in k.lower()}
                    if vlan_fields:
                        print(f"      🎯 VLAN/Isolation fields in popup:")
                        for k, v in vlan_fields.items():
                            print(f"         {k} = {v}")

                    # Close popup and switch back to main window
                    self.driver.close()
                    self.driver.switch_to.window(main_window)
                    time.sleep(0.5)
                else:
                    current_url = self.driver.current_url
                    print(f"      Current URL: {current_url}")

                # Only click first 4 Edit buttons (wifix SSIDs) to save time
                if i >= 3:
                    print(f"\n   ⏭️  Skipping remaining Edit buttons (captured {i+1} already)")
                    break

        # Handle any popups that might have opened
        self.find_and_handle_popups()

    def test_save_apply_workflow(self):
        """Test the Save and Apply workflow"""
        print(f"\n{'='*60}")
        print("💾 Testing Save/Apply Workflow")
        print(f"{'='*60}")

        # Look for Save button
        try:
            save_buttons = self.driver.find_elements(By.XPATH, "//button[contains(text(), 'Save')] | //input[@value='Save']")

            if save_buttons:
                print(f"✅ Found {len(save_buttons)} Save button(s)")

                # Click first Save button
                print("   Clicking Save button...")
                self.driver.execute_script("arguments[0].click();", save_buttons[0])
                time.sleep(3)

                # Look for Apply button
                apply_buttons = self.driver.find_elements(By.XPATH, "//button[contains(text(), 'Apply')] | //input[@value='Apply']")

                if apply_buttons:
                    print(f"✅ Found {len(apply_buttons)} Apply button(s)")
                    print("   Clicking Apply button...")
                    self.driver.execute_script("arguments[0].click();", apply_buttons[0])
                    time.sleep(3)
                    print("✅ Apply clicked")
                else:
                    print("   No Apply button found")
            else:
                print("   No Save button found")

        except Exception as e:
            print(f"❌ Error in Save/Apply workflow: {e}")

    def capture_page_state(self, name="page"):
        """Capture current page state including HTML and screenshot"""
        print(f"\n📸 Capturing page state: {name}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save HTML
        html_file = f"{name}_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(self.driver.page_source)
        print(f"   Saved HTML to {html_file}")

        # Save screenshot
        screenshot_file = f"{name}_{timestamp}.png"
        self.driver.save_screenshot(screenshot_file)
        print(f"   Saved screenshot to {screenshot_file}")

        # Save current URL
        url_file = f"{name}_{timestamp}_url.txt"
        with open(url_file, 'w') as f:
            f.write(self.driver.current_url)
        print(f"   Saved URL to {url_file}")

    def run_full_analysis(self):
        """Run complete automated analysis"""
        try:
            # Start MITM proxy
            self.start_mitm_proxy()

            # Start browser
            self.start_browser()

            # Login
            if not self.login():
                print("❌ Login failed, aborting")
                return

            # Capture initial state
            self.capture_page_state("01_after_login")

            # Navigate to wireless
            self.navigate_to_wireless()
            self.capture_page_state("02_wireless_main")

            # Extract main page fields
            main_fields = self.get_all_form_fields()
            with open("wireless_main_fields.json", 'w') as f:
                json.dump(main_fields, f, indent=2)

            # Click Edit buttons and handle popups
            self.click_edit_buttons()
            self.capture_page_state("03_after_edit_clicks")

            # Test Save/Apply workflow
            self.test_save_apply_workflow()
            self.capture_page_state("04_after_save_apply")

            # Wait a bit for any async requests
            print("\n⏳ Waiting for any pending requests...")
            time.sleep(5)

            print(f"\n{'='*60}")
            print("✅ ANALYSIS COMPLETE")
            print(f"{'='*60}")
            print("Check the luci_capture_* directory for captured requests")
            print("Check the *_fields.json files for form field data")
            print("Check the *.html and *.png files for page states")

        except Exception as e:
            print(f"\n❌ Error during analysis: {e}")
            import traceback
            traceback.print_exc()

        finally:
            # Cleanup
            print(f"\n{'='*60}")
            print("🧹 Cleaning up")
            print(f"{'='*60}")

            if self.driver:
                print("   Closing browser...")
                self.driver.quit()

            self.stop_mitm_proxy()

            print("✅ Cleanup complete")

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Automated Luci Interface Analyzer')
    parser.add_argument('--host', default='172.19.4.10', help='AP host address')
    parser.add_argument('--username', default='admin', help='Login username')
    parser.add_argument('--password', required=True, help='Login password')
    parser.add_argument('--proxy-port', type=int, default=8888, help='MITM proxy port')

    args = parser.parse_args()

    analyzer = LuciAnalyzer(
        host=args.host,
        username=args.username,
        password=args.password,
        proxy_port=args.proxy_port
    )

    analyzer.run_full_analysis()

if __name__ == '__main__':
    main()

