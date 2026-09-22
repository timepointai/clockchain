#!/usr/bin/env python3
"""Verify Fly image identities and the single-writer scheduled tick contract."""
import json
import sys


def group(machines, name):
    found = [m for m in machines if m.get('config', {}).get('metadata', {}).get('fly_process_group') == name]
    if len(found) != 1:
        raise ValueError(f'expected exactly one {name} machine, found {len(found)}')
    return found[0]


def digest(machine):
    resolved = machine.get('image_ref', {}).get('digest')
    image = machine.get('config', {}).get('image', '')
    value = resolved or (image.split('@', 1)[1] if '@' in image else '')
    if not value.startswith('sha256:') or len(value) != 71:
        raise ValueError('machine does not expose an immutable image digest')
    return value


def verify(machines, expected=None):
    app, tick = group(machines, 'app'), group(machines, 'tick')
    if app.get('state') != 'started':
        raise ValueError('app is not started')
    if not app['config'].get('mounts'):
        raise ValueError('app has no media mount')
    if tick['config'].get('schedule') != 'hourly':
        raise ValueError('tick is not hourly')
    if tick['config'].get('restart', {}).get('policy') != 'no':
        raise ValueError('tick restart must be no')
    if expected and (digest(app) != expected or digest(tick) != expected):
        raise ValueError('app/tick release digests differ')
    return {'app': app['id'], 'tick': tick['id'], 'app_digest': digest(app), 'tick_digest': digest(tick)}


if __name__ == '__main__':
    print(json.dumps(verify(json.load(sys.stdin), sys.argv[1] if len(sys.argv) > 1 else None)))
