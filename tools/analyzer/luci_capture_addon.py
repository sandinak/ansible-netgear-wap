#!/usr/bin/env python3
"""
MITM Proxy addon for capturing LuCI traffic.
Used by automated_luci_analyzer.py to log HTTP requests/responses.
"""

from mitmproxy import http
import json
from datetime import datetime
from pathlib import Path


class LuciCapture:
    """Captures and logs LuCI HTTP traffic."""
    
    def __init__(self):
        self.log_dir = Path("luci_capture_logs")
        self.log_dir.mkdir(exist_ok=True)
        self.request_count = 0
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Log outgoing requests."""
        self.request_count += 1
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "request",
            "count": self.request_count,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
        }
        
        # Capture POST data
        if flow.request.method == "POST":
            try:
                log_entry["post_data"] = flow.request.get_text()
            except:
                log_entry["post_data"] = "<binary>"
        
        self._write_log(log_entry)
        
    def response(self, flow: http.HTTPFlow) -> None:
        """Log incoming responses."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "response",
            "url": flow.request.pretty_url,
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "content_length": len(flow.response.content) if flow.response.content else 0,
        }
        
        # For HTML responses, capture content
        content_type = flow.response.headers.get("content-type", "")
        if "text/html" in content_type and flow.response.content:
            try:
                log_entry["content_preview"] = flow.response.get_text()[:1000]
            except:
                pass
        
        self._write_log(log_entry)
        
    def _write_log(self, entry: dict) -> None:
        """Write log entry to file."""
        log_file = self.log_dir / "traffic.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")


addons = [LuciCapture()]

