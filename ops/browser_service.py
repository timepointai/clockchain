#!/usr/bin/env python3
"""Install/manage the single Clockchain browser as a macOS login service."""
import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import webbrowser

import browse

LABEL = 'com.clockchain.browser'


def configuration(config_path, python=sys.executable):
    path = browse.policy.private(config_path)
    browse.config_read(path)
    return {'Label': LABEL,
            'ProgramArguments': [str(Path(python).resolve()), str(Path(__file__).with_name('browse.py').resolve()), '--config', str(path)],
            'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 5,
            'WorkingDirectory': str(Path(__file__).resolve().parent.parent),
            'EnvironmentVariables': {'HOME': str(Path.home()), 'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'},
            'StandardOutPath': str(path.parent/'browser.stdout.log'),
            'StandardErrorPath': str(path.parent/'browser.stderr.log')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'restart', 'stop', 'status', 'open', 'uninstall'])
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('Use browse.py directly with your platform service manager.')
    domain = f'gui/{os.getuid()}'
    target = domain+'/'+LABEL
    plist = Path.home()/'Library/LaunchAgents'/f'{LABEL}.plist'
    if args.action == 'install':
        if not args.config:
            parser.error('--config is required for install')
        value = configuration(args.config)
        if plist.exists():
            old = plistlib.loads(plist.read_bytes())
            if old.get('Label') != LABEL or old.get('ProgramArguments', [None, None])[1] != value['ProgramArguments'][1]:
                parser.error('Existing service belongs to another program.')
            subprocess.run(['launchctl', 'bootout', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_bytes(plistlib.dumps(value))
        plist.chmod(0o600)
        subprocess.run(['launchctl', 'bootstrap', domain, str(plist)], check=True)
    elif args.action == 'restart':
        subprocess.run(['launchctl', 'kickstart', '-k', target], check=True)
    elif args.action in ('stop', 'uninstall'):
        subprocess.run(['launchctl', 'bootout', target], check=True)
        if args.action == 'uninstall':
            plist.unlink()
    elif args.action == 'status':
        subprocess.run(['launchctl', 'print', target], check=True)
    elif args.action == 'open':
        config_path = args.config or Path(plistlib.loads(plist.read_bytes())['ProgramArguments'][-1])
        config = browse.config_read(config_path)
        webbrowser.open(f'http://127.0.0.1:{config.get("port", 8766)}/')


if __name__ == '__main__':
    main()
