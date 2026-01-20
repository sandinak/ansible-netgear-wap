# Extending the Collection to New Models

This guide explains how to analyze a new NETGEAR WAX model and extend the collection.

## Supported Models

| Model  | Auth Hash | SSID Popup Endpoint | Notes |
|--------|-----------|---------------------|-------|
| WAX210 | SHA-512   | wifi_Encryption_P2P | 4 SSIDs per radio |
| WAX218 | MD5       | wifi_Encryption_Combined | 8 SSIDs per radio |

## Prerequisites

1. Firefox browser installed
2. geckodriver installed (`brew install geckodriver` on macOS)
3. Python dependencies installed via Makefile

## Step 1: Run the Analyzer

```bash
make analyze HOST=<AP_IP> PASSWORD=<password>
```

This will:
- Open Firefox with a MITM proxy
- Login to the LuCI interface
- Navigate through wireless settings
- Click edit buttons to open popup forms
- Capture all HTTP traffic and form fields

## Step 2: Analyze the Output

The analyzer creates a timestamped directory with:

| File | Contents |
|------|----------|
| `*_fields.json` | Form field names and values |
| `*.html` | Page source at each stage |
| `*.png` | Screenshots |
| `luci_capture_*` | MITM proxy logs |

### Key Things to Look For

1. **Form Field Names**: Look for `cbid.*` patterns
   - Format: `cbid.<config>.<section>.<option>`
   - Example: `cbid.wireless.wifi0_ssid_1.ssid`

2. **Popup Form URLs**: Note the popup window URLs
   - SSID config: `/admin/network/wifi_Encryption_P2P`
   - Channel config: `/admin/network/wifi_Channel`

3. **CSRF Tokens**: Look for hidden fields like `val_csrf` or `snid`

4. **API Endpoints**: Check MITM logs for JSON API calls
   - Interface status: `/admin/network/iface_status2/...`
   - UCI changes: `/admin/system/ajax_get_uci_wifi_network_changes`

## Step 3: Document the Model

Create a model-specific document in `docs/models/`:

```markdown
# NETGEAR WAX<MODEL> Technical Reference

## Firmware Version
- Tested: V1.x.x.xx

## Authentication
- Method: SHA-512 hash of password + newline
- Session: stok token in URL, sysauth cookie

## Endpoints
| Function | URL |
|----------|-----|
| Login | /cgi-bin/luci |
| Wireless | /admin/network/wireless_device |
| SSID Config | /admin/network/wifi_Encryption_P2P |

## Form Fields
| Setting | Field Name |
|---------|------------|
| SSID Name | cbid.wireless.wifiX_ssid_N.ssid |
| VLAN | cbid.wireless.wifiX_ssid_N.network |
```

## Step 4: Create/Modify Module

1. Copy an existing module as a template
2. Update the API class with new endpoints
3. Update form field names if different
4. Test thoroughly with check mode first

## Common Patterns Across WAX Models

### Authentication (likely same for all)
```python
hashed_pw = hashlib.sha512((password + "\n").encode()).hexdigest()
```

### Session Token Extraction
```python
stok_match = re.search(r';stok=([a-f0-9]+)', response_body)
```

### Form Submission
```python
form_data = {
    'cbid.wireless.wifi0_ssid_1.ssid': 'MySSID',
    'apply_form_submit': '1',
    'apply_val_csrf': csrf_token,
}
```

## Troubleshooting

### Login Fails
- Check password hash method (SHA-512 vs MD5)
- Verify the `is_login=1` cookie is set
- Check for firmware-specific login fields

### Form Submission Fails
- Capture the exact form fields from browser dev tools
- Check for missing CSRF tokens
- Verify the submit URL and method

### Changes Don't Apply
- Look for "Save & Apply" vs "Save" buttons
- Check for `/admin/uci/saveapply` endpoint
- Some changes require device reboot

