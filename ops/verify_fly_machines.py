#!/usr/bin/env python3
"""Verify Fly image identities and the single-writer scheduled tick contract.

v1 launches without a tick: `verify_v1` requires that no machine is scheduled
and that nothing but the single app machine is running.
"""
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


def verify_v1(machines, expected=None):
    """One started app on the expected digest; no tick running or scheduled.

    The v0 tick writes v0 events. Any scheduled machine, any machine in the
    tick group that is not stopped, and any other running machine is refused,
    so a tick cannot fire against the v1 database under another name either.
    """
    app = group(machines, 'app')
    if app.get('state') != 'started':
        raise ValueError('app is not started')
    for machine in machines:
        config = machine.get('config', {})
        name = config.get('metadata', {}).get('fly_process_group')
        if config.get('schedule'):
            raise ValueError(f'v1 forbids scheduled machines; {name or "unnamed"} has schedule '
                             f'{config["schedule"]!r}')
        if name == 'tick' and machine.get('state') not in ('stopped', 'destroyed'):
            raise ValueError('a tick machine is ' + str(machine.get('state')))
        if machine is not app and machine.get('state') not in ('stopped', 'destroyed'):
            raise ValueError(f'unexpected running machine in group {name or "unnamed"}')
    if expected and digest(app) != expected:
        raise ValueError('app release digest differs')
    return {'app': app['id'], 'app_digest': digest(app),
            'ticks': [m['id'] for m in machines
                      if m.get('config', {}).get('metadata', {}).get('fly_process_group') == 'tick']}


if __name__ == '__main__':
    print(json.dumps(verify(json.load(sys.stdin), sys.argv[1] if len(sys.argv) > 1 else None)))
