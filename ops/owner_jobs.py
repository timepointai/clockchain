"""Shared plumbing for the owner's scheduled jobs on macOS (launchd).

The jobs (`schedule_backups.py`, `monitor_v1.py`) run from the owner's
workstation, never from CI or a cloud session. Their configuration comes from
a private env file (mode 0600, outside this checkout) named on the command
line, so no secret value lands in a plist, argv or log. Each run writes a status JSON
into a private state directory and raises a macOS notification on failure.
Errors are recorded by type and a redacted message: any value from the env
file is replaced before it is written or printed.
"""
import datetime
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LABEL_PREFIX = 'local.clockchain.'
NAME = re.compile(r'[A-Z][A-Z0-9_]*')
REDACTED = '[redacted]'


class ConfigError(ValueError):
    """The private env file or a private directory is unsafe or incomplete."""


def outside_checkout(path, root=ROOT):
    path = Path(path).absolute()  # unresolved, so callers' symlink checks still see a link
    resolved = path.resolve()
    if resolved == root or resolved.is_relative_to(root):
        raise ConfigError(f'{resolved.name}: private files must be outside the public checkout')
    return path


def load_env_file(path, root=ROOT):
    """KEY=VALUE lines from a private file: owned by this user, mode 0600 or stricter."""
    path = outside_checkout(path, root)
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise ConfigError('env file does not exist') from None
    if not path.is_file() or path.is_symlink():
        raise ConfigError('env file must be a regular file')
    if info.st_uid != os.getuid():
        raise ConfigError('env file must be owned by the current user')
    if info.st_mode & 0o077:
        raise ConfigError('env file must not be readable by group or others (chmod 600)')
    env = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        name, sep, value = line.partition('=')
        if not sep or not NAME.fullmatch(name):
            raise ConfigError(f'env file line {number} is not NAME=value')
        env[name] = value
    return env


def require(env, *names):
    missing = [n for n in names if not env.get(n)]
    if missing:
        raise ConfigError('env file needs: ' + ', '.join(missing))
    return [env[n] for n in names]


def private_dir(path, root=ROOT):
    """Create (0700) or accept an existing directory nobody else can read."""
    path = outside_checkout(path, root)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if path.is_symlink() or not path.is_dir():
        raise ConfigError(f'{path.name} must be a real directory')
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ConfigError(f'{path.name} must be owned by this user with mode 0700')
    return path


def redact(text, env):
    """Replace every env-file value (four characters or longer) in `text`."""
    text = str(text)
    for value in sorted((v for v in env.values() if len(v) >= 4), key=len, reverse=True):
        text = text.replace(value, REDACTED)
    return text


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp(moment=None):
    return (moment or now()).strftime('%Y%m%dT%H%M%SZ')


def write_status(path, doc):
    """Atomically replace a 0600 status JSON."""
    path = Path(path)
    tmp = path.with_name('.' + path.name + '.tmp')
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(doc, f, indent=2)
        f.write('\n')
    os.replace(tmp, path)
    return doc


def notify(title, message, runner=subprocess.run):
    """macOS notification through osascript; text travels as argv, not script."""
    script = ['-e', 'on run argv', '-e',
              'display notification (item 2 of argv) with title (item 1 of argv)', '-e', 'end run']
    try:
        return runner(['osascript', *script, title, message], capture_output=True,
                      timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class JobLock:
    """One run of a job at a time: a non-blocking flock in the state directory."""

    def __init__(self, state_dir, name):
        self.path = Path(state_dir) / (name + '.lock')
        self.file = None

    def __enter__(self):
        self.file = open(self.path, 'a')
        try:
            fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.file.close()
            self.file = None
            return False
        return True

    def __exit__(self, *exc):
        if self.file:
            self.file.close()
        return False


# --- launchd ---------------------------------------------------------------

def parse_time(value):
    match = re.fullmatch(r'([01]?[0-9]|2[0-3]):([0-5][0-9])', value or '')
    if not match:
        raise ValueError('--time must be HH:MM (24-hour, local time)')
    return int(match.group(1)), int(match.group(2))


def plist(label, script, env_file, log_dir, *, calendar=None, interval=None, python=None,
          path_env=None):
    """A LaunchAgent plist. It names files only; values stay in the env file."""
    if (calendar is None) == (interval is None):
        raise ValueError('a job has exactly one schedule')
    doc = {'Label': label,
           'ProgramArguments': [python or sys.executable,
                                str(Path(script).resolve()), 'run', '--env-file',
                                str(Path(env_file).resolve())],
           'WorkingDirectory': str(ROOT),
           'EnvironmentVariables': {'PATH': path_env or os.environ.get(
               'PATH', '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin')},
           'StandardOutPath': str(Path(log_dir) / (label + '.log')),
           'StandardErrorPath': str(Path(log_dir) / (label + '.log')),
           'RunAtLoad': False, 'ProcessType': 'Background'}
    if calendar is not None:
        doc['StartCalendarInterval'] = {'Hour': calendar[0], 'Minute': calendar[1]}
    else:
        doc['StartInterval'] = int(interval)
    return plistlib.dumps(doc, sort_keys=True)


def agents_dir():
    return Path.home() / 'Library' / 'LaunchAgents'


def install(label, data, *, directory=None, runner=subprocess.run):
    """Write the plist and (re)load it into the user's launchd domain."""
    directory = Path(directory or agents_dir())
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (label + '.plist')
    domain = f'gui/{os.getuid()}'
    runner(['launchctl', 'bootout', f'{domain}/{label}'], capture_output=True)
    tmp = path.with_name('.' + path.name + '.tmp')
    tmp.write_bytes(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    runner(['launchctl', 'bootstrap', domain, str(path)], check=True, capture_output=True)
    return path


def remove(label, *, directory=None, runner=subprocess.run):
    """Unload the job (if loaded) and delete its plist."""
    path = Path(directory or agents_dir()) / (label + '.plist')
    runner(['launchctl', 'bootout', f'gui/{os.getuid()}/{label}'], capture_output=True)
    existed = path.exists()
    path.unlink(missing_ok=True)
    return existed
