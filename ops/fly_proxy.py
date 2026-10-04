"""A short-lived localhost `flyctl proxy` that this process starts and alone stops.

The scheduled backup and monitor jobs reach the private node through
`flyctl proxy <port>:80 <app>.flycast --bind-addr 127.0.0.1` on a fresh random
loopback port. Ownership rules:

- Only the Popen this object created is ever signalled, and only through that
  Popen handle. Nothing here signals by name, by port or with pkill/killall.
- An existing proxy, the owner's own interactive one included, is never reused
  and never touched.
- A pidfile per job (`fly-proxy-<job>.json`) in the private state directory
  records the exact argv of the running proxy. Callers hold that job's lock,
  so a pidfile they find was left by a previous run of the same job that died
  before its cleanup ran. That orphan is stopped only when the recorded pid is
  alive AND its command line is exactly the recorded argv (random port
  included). Anything else is left running; only the stale pidfile goes.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

READY_ATTEMPTS = 30


class ProxyFailed(RuntimeError):
    """The proxy exited or never answered /health."""


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def health_status(url, timeout=5):
    try:
        with urllib.request.urlopen(url + '/health', timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def command_line(pid, runner=subprocess.run):
    """The full command line of a live pid (macOS and Linux `ps`), or None."""
    result = runner(['ps', '-ww', '-o', 'command=', '-p', str(int(pid))], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, but owned by someone else: certainly not ours to stop
    return True


class FlyProxy:
    def __init__(self, app, state_dir, job, *, flyctl='flyctl', popen=subprocess.Popen,
                 probe=health_status, sleep=time.sleep, runner=subprocess.run):
        if not job.isidentifier():
            raise ValueError('job name must be an identifier')
        self.app, self.state_dir, self.job, self.flyctl = app, Path(state_dir), job, flyctl
        self.popen, self.probe, self.sleep, self.runner = popen, probe, sleep, runner
        self.proc = None
        self.started_pid = None
        self.argv = None
        self.url = None
        self.reaped = None

    @property
    def pidfile(self):
        return self.state_dir / f'fly-proxy-{self.job}.json'

    def reap_orphan(self):
        """Stop a proxy a previous run of this job started and could not clean up."""
        try:
            record = json.loads(self.pidfile.read_text())
        except FileNotFoundError:
            return None
        except ValueError:
            record = {}
        pid, argv = record.get('pid'), record.get('argv')
        outcome = 'stale_pidfile_removed'
        if type(pid) is int and pid > 1 and isinstance(argv, list) and alive(pid) and \
                command_line(pid, self.runner) == ' '.join(argv):
            os.kill(pid, signal.SIGTERM)
            outcome = 'orphan_stopped'
        self.pidfile.unlink(missing_ok=True)
        return outcome

    def start(self):
        if self.proc is not None:
            raise RuntimeError('proxy already started')
        self.reaped = self.reap_orphan()
        port = free_port()
        self.argv = [self.flyctl, 'proxy', f'{port}:80', self.app + '.flycast', '-a', self.app,
                     '--bind-addr', '127.0.0.1']
        log = open(self.state_dir / f'fly-proxy-{self.job}.log', 'ab')
        try:
            self.proc = self.popen(self.argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        finally:
            log.close()
        self.started_pid = self.proc.pid
        fd = os.open(self.pidfile, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump({'pid': self.started_pid, 'argv': self.argv}, f)
        self.url = f'http://127.0.0.1:{port}'
        for attempt in range(READY_ATTEMPTS):
            if self.proc.poll() is not None:
                raise ProxyFailed('fly proxy exited before it answered')
            try:
                if self.probe(self.url) == 200 and self.proc.poll() is None:
                    return self.url
            except OSError:
                pass
            self.sleep(1)
        raise ProxyFailed('fly proxy did not answer /health')

    def stop(self):
        """Stop the proxy this object started, through its own Popen handle only."""
        proc, self.proc = self.proc, None
        if proc is None:
            return
        if proc.pid != self.started_pid:
            raise RuntimeError('refusing to signal a process this proxy did not start')
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        try:
            if json.loads(self.pidfile.read_text()).get('pid') == self.started_pid:
                self.pidfile.unlink()
        except (FileNotFoundError, ValueError):
            pass

    def __enter__(self):
        try:
            return self.start()
        except BaseException:
            self.stop()
            raise

    def __exit__(self, *exc):
        self.stop()
        return False
