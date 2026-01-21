#!/usr/bin/env python3
"""Quick login test for all WAX devices."""
import urllib.request
import ssl
import hashlib
import os
import sys

devices = [
    ('WAX210', '172.19.4.10'),
    ('WAX218', '172.19.4.14'),
    ('WAX210-2', '172.19.4.16'),
]

password = os.environ.get('WAX_PASSWORD')
if not password:
    print("ERROR: Set WAX_PASSWORD environment variable")
    sys.exit(1)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

for name, host in devices:
    print(f"\n{'='*60}")
    print(f"Testing {name} at {host}")
    print('='*60)
    
    try:
        base_url = f"https://{host}"
        login_url = f"{base_url}/cgi-bin/luci"
        
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor()
        )
        
        req = urllib.request.Request(login_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        response = opener.open(req, timeout=10)
        body = response.read().decode('utf-8')
        
        print(f"  Connected - got {len(body)} bytes")
        
        uses_sha512 = 'sha512sum' in body
        print(f"  Auth type: {'SHA-512' if uses_sha512 else 'MD5'}")
        
        if uses_sha512:
            hashed = hashlib.sha512((password + '\n').encode()).hexdigest()
        else:
            hashed = hashlib.md5((password + '\n').encode()).hexdigest()
        
        login_data = f"username=admin&password={hashed}&agree=1&account=admin"
        req = urllib.request.Request(login_url, data=login_data.encode())
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0')
        req.add_header('Referer', login_url)
        req.add_header('Origin', base_url)
        req.add_header('Cookie', 'is_login=1')
        
        response = opener.open(req, timeout=10)
        final_url = response.geturl()
        body = response.read().decode('utf-8')
        
        print(f"  Final URL: {final_url[:80]}...")
        
        if 'stok=' in final_url:
            print(f"  ✅ LOGIN SUCCESS (stok in URL)")
        elif 'stok=' in body:
            import re
            stok = re.search(r'stok=([a-f0-9]+)', body)
            if stok:
                print(f"  ✅ LOGIN SUCCESS (stok in body)")
            else:
                print(f"  ❌ LOGIN FAILED")
        else:
            print(f"  ❌ LOGIN FAILED - no stok found")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")

