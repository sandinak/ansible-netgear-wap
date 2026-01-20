# WAX AP Analyzer Tools

Tools for analyzing NETGEAR WAX series access points to discover endpoints, forms, and API structures.

## Tools

- **automated_luci_analyzer.py** - Selenium-based tool that automates Firefox to crawl the LuCI web interface
- **luci_capture_addon.py** - MITM proxy addon for capturing HTTP traffic

## Usage

From the repository root:

```bash
make analyze HOST=172.19.4.14 PASSWORD=yourpassword
```

This will:
1. Set up a Python virtual environment with Selenium and mitmproxy
2. Check for geckodriver and Firefox
3. Launch the analyzer against the specified AP

## Requirements

- Firefox browser
- geckodriver (`brew install geckodriver` on macOS)
- Python 3.8+

## Output

The analyzer creates several output files:
- `*.html` - Captured page sources
- `*.png` - Screenshots
- `*_fields.json` - Extracted form fields
- `luci_capture_logs/` - MITM proxy logs

## Adding New Models

1. Run the analyzer against the new model
2. Compare the captured data with existing models
3. Update the modules in `plugins/modules/` to handle any differences

## Supported Models

| Model  | Auth Type | SSID Popup Endpoint |
|--------|-----------|---------------------|
| WAX210 | SHA-512   | wifi_Encryption_P2P |
| WAX218 | MD5       | wifi_Encryption_Combined |

