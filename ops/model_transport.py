#!/usr/bin/env python3
"""Credential-isolated OpenRouter transport. Parent enforces total wall deadline."""
import argparse
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('redirect refused')


def public_json(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=30) as response: raw = response.read(8_000_001)
    if len(raw) > 8_000_000: raise ValueError('catalog size limit')
    return json.loads(raw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--request', type=Path, required=True)
    p.add_argument('--response', type=Path, required=True)
    args = p.parse_args()
    token = os.environ.get('OPENROUTER_API_KEY')
    if not token: raise ValueError('OPENROUTER_API_KEY required')
    request = urllib.request.Request('https://openrouter.ai/api/v1/chat/completions',
        data=args.request.read_bytes(), headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    fd = os.open(args.response, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb', buffering=0) as retained:
        try: response = opener.open(request, timeout=90)
        except urllib.error.HTTPError as error: response = error
        with response:
            size = 0
            while True:
                data = response.read1(65536)
                if not data: break
                retained.write(data); size += len(data)
                if size > 8_000_000: raise ValueError('response byte limit exceeded')
            if response.status != 200:
                print(json.dumps({'transport_error':'http','status':response.status}))
                return 1
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'transport_error':type(error).__name__}))
        raise SystemExit(1)
