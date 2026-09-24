#!/usr/bin/env python3
"""Install a credential-free daily discovery job on the owner's Mac."""
import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys

import model_policy as policy


def configuration(registry, hour):
    registry = policy.private(registry)
    policy.integer(hour, 0, 23)
    return {
        'Label': 'ai.timepoint.clockchain.model-discovery',
        'ProgramArguments': [sys.executable, str(Path(__file__).with_name('model_catalog.py').resolve()),
                             '--registry', str(registry), 'refresh'],
        'StartCalendarInterval': {'Hour': hour, 'Minute': 0},
        'RunAtLoad': True,
        'StandardOutPath': str(registry/'daily-discovery.log'),
        'StandardErrorPath': str(registry/'daily-discovery-error.log'),
        'Umask': 0o077,
        # No API keys, database access, or inference/generation command.
        'EnvironmentVariables': {'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--hour', type=int, default=9)
    args = parser.parse_args()
    if sys.platform != 'darwin': parser.error('use model_catalog.py refresh from your operating-system scheduler')
    config = configuration(args.registry, args.hour)
    registry = policy.private(args.registry); registry.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = Path.home()/'Library/LaunchAgents'/str(config['Label']+'.plist')
    path.parent.mkdir(parents=True, exist_ok=True)
    domain = 'gui/'+str(os.getuid())
    if path.exists(): subprocess.run(['launchctl','bootout',domain,str(path)],capture_output=True)
    path.write_bytes(plistlib.dumps(config)); path.chmod(0o600)
    subprocess.run(['launchctl','bootstrap',domain,str(path)],check=True)
    print('Daily free catalog review installed: '+str(path))


if __name__ == '__main__': main()
