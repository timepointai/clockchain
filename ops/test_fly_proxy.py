"""FlyProxy against real processes: a fake `flyctl` that serves /health on loopback.

Nothing here reaches Fly. The fake `flyctl` accepts only the exact argv
FlyProxy builds and serves GET /health on 127.0.0.1:PORT until terminated.
"""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import fly_proxy
from fly_proxy import FlyProxy, ProxyFailed, alive, command_line, free_port

APP = 'cc-test-app'

FAKE_FLYCTL = '''#!{python}
import http.server
import sys

args = sys.argv[1:]
if (len(args) != 7 or args[0] != 'proxy' or not args[1].endswith(':80')
        or args[3] != '-a' or args[2] != args[4] + '.flycast'
        or args[5:] != ['--bind-addr', '127.0.0.1']):
    sys.exit(2)
port = int(args[1].split(':')[0])


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            body = b'{{"status":"ok"}}'
            self.send_response(200)
        else:
            body = b'not found'
            self.send_response(404)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer(('127.0.0.1', port), Handler).serve_forever()
'''

EXITS_AT_ONCE = '#!{python}\nimport sys\nsys.exit(1)\n'
NEVER_ANSWERS = '#!{python}\nimport time\ntime.sleep(60)\n'


def health(url, timeout=2):
    try:
        with urllib.request.urlopen(url + '/health', timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return None


def wait_for_health(url, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if health(url, timeout=1) == 200:
            return True
        time.sleep(0.05)
    return False


def proxy_args(port, app=APP):
    return ['proxy', f'{port}:80', app + '.flycast', '-a', app, '--bind-addr', '127.0.0.1']


class FlyProxyProcessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.bin = base / 'bin'
        self.state = base / 'state'
        self.bin.mkdir()
        self.state.mkdir(mode=0o700)
        self.flyctl = self.script('flyctl', FAKE_FLYCTL)

    def script(self, name, template):
        path = self.bin / name
        path.write_text(template.format(python=sys.executable))
        path.chmod(0o755)
        return str(path)

    def spawn(self, argv):
        """A process this test owns; always stopped at cleanup."""
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

        def stop():
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        self.addCleanup(stop)
        return proc

    def proxy(self, flyctl=None, job='backup'):
        proxy = FlyProxy(APP, self.state, job, flyctl=flyctl or self.flyctl,
                         sleep=lambda _: time.sleep(0.1))
        self.addCleanup(self.stop_quietly, proxy)
        return proxy

    @staticmethod
    def stop_quietly(proxy):
        try:
            proxy.stop()
        except RuntimeError:
            pass

    def pidfile(self, job='backup'):
        return self.state / f'fly-proxy-{job}.json'

    def write_pidfile(self, record, job='backup'):
        self.pidfile(job).write_text(json.dumps(record) if not isinstance(record, str) else record)

    def assert_survives(self, proc):
        with self.assertRaises(subprocess.TimeoutExpired):
            proc.wait(timeout=0.3)
        self.assertIsNone(proc.poll())

    def foreign_proxy(self, prefix=()):
        """A running proxy-looking process this FlyProxy did not start."""
        port = free_port()
        proc = self.spawn([*prefix, self.flyctl, *proxy_args(port)])
        self.assertTrue(wait_for_health(f'http://127.0.0.1:{port}'), 'fake flyctl did not start')
        return proc, port

    # --- start / stop --------------------------------------------------------

    def test_start_serves_health_records_pidfile_and_stop_removes_both(self):
        proxy = self.proxy()
        with proxy as url:
            self.assertRegex(url, r'^http://127\.0\.0\.1:\d+$')
            port = int(url.rsplit(':', 1)[1])
            self.assertEqual(health(url), 200)
            pid = proxy.proc.pid
            self.assertEqual(proxy.started_pid, pid)
            self.assertIsNone(proxy.reaped)
            self.assertEqual(stat.S_IMODE(self.pidfile().stat().st_mode), 0o600)
            self.assertEqual(json.loads(self.pidfile().read_text()),
                             {'pid': pid, 'argv': [self.flyctl, *proxy_args(port)]})
            self.assertTrue(alive(pid))
            with self.assertRaisesRegex(RuntimeError, 'already started'):
                proxy.start()
        self.assertFalse(self.pidfile().exists())
        self.assertIsNone(proxy.proc)
        self.assertFalse(alive(pid))
        self.assertIsNone(health(url, timeout=1))

    def test_pidfiles_are_per_job(self):
        backup, monitor = self.proxy(job='backup'), self.proxy(job='monitor')
        with backup as one, monitor as two:
            self.assertNotEqual(one, two)
            self.assertEqual(json.loads(self.pidfile('backup').read_text())['pid'], backup.started_pid)
            self.assertEqual(json.loads(self.pidfile('monitor').read_text())['pid'], monitor.started_pid)
            self.assertEqual((health(one), health(two)), (200, 200))
        self.assertFalse(self.pidfile('backup').exists())
        self.assertFalse(self.pidfile('monitor').exists())

    # --- ownership guard -------------------------------------------------------

    def test_an_existing_proxy_for_the_same_app_is_never_touched(self):
        foreign, port = self.foreign_proxy()
        proxy = self.proxy()
        with proxy as url:
            self.assertNotEqual(url, f'http://127.0.0.1:{port}')
            self.assertNotEqual(proxy.started_pid, foreign.pid)
            self.assertIsNone(proxy.reaped)
        self.assert_survives(foreign)
        self.assertEqual(health(f'http://127.0.0.1:{port}'), 200)

    def test_pidfile_naming_a_live_process_with_other_argv_spares_it(self):
        foreign, port = self.foreign_proxy(prefix=(sys.executable,))
        real = [sys.executable, self.flyctl, *proxy_args(port)]
        self.assertEqual(command_line(foreign.pid), ' '.join(real))
        cases = {
            'different port': [sys.executable, self.flyctl, *proxy_args(port + 1)],
            'missing interpreter': [self.flyctl, *proxy_args(port)],
            'different app': [sys.executable, self.flyctl, *proxy_args(port, 'other-app')],
        }
        for name, argv in cases.items():
            with self.subTest(name):
                self.write_pidfile({'pid': foreign.pid, 'argv': argv})
                proxy = self.proxy()
                with proxy:
                    self.assertEqual(proxy.reaped, 'stale_pidfile_removed')
                    record = json.loads(self.pidfile().read_text())
                    self.assertEqual(record['pid'], proxy.started_pid)
                self.assertFalse(self.pidfile().exists())
                self.assert_survives(foreign)
                self.assertEqual(health(f'http://127.0.0.1:{port}'), 200)

    def test_malformed_pidfile_records_never_signal(self):
        foreign, port = self.foreign_proxy(prefix=(sys.executable,))
        real = [sys.executable, self.flyctl, *proxy_args(port)]
        for name, record in {
                'argv as a string': {'pid': foreign.pid, 'argv': ' '.join(real)},
                'pid as a string': {'pid': str(foreign.pid), 'argv': real},
                'pid as a bool': {'pid': True, 'argv': real},
                'no argv': {'pid': foreign.pid},
                'not json': '{"pid": %d, ' % foreign.pid}.items():
            with self.subTest(name):
                self.write_pidfile(record)
                proxy = self.proxy()
                with proxy:
                    self.assertEqual(proxy.reaped, 'stale_pidfile_removed')
                self.assert_survives(foreign)

    def test_orphan_with_exactly_the_recorded_argv_is_stopped(self):
        port = free_port()
        argv = [sys.executable, self.flyctl, *proxy_args(port)]
        orphan = self.spawn(argv)
        self.assertTrue(wait_for_health(f'http://127.0.0.1:{port}'))
        self.assertEqual(command_line(orphan.pid), ' '.join(argv))
        self.write_pidfile({'pid': orphan.pid, 'argv': argv})
        proxy = self.proxy()
        with proxy as url:
            self.assertEqual(proxy.reaped, 'orphan_stopped')
            self.assertEqual(orphan.wait(timeout=10), -signal.SIGTERM)
            self.assertEqual(json.loads(self.pidfile().read_text())['pid'], proxy.started_pid)
            self.assertEqual(health(url), 200)
        self.assertFalse(self.pidfile().exists())

    def test_pidfile_naming_a_dead_pid_is_just_removed(self):
        dead = self.spawn([sys.executable, '-c', 'pass'])
        dead.wait()
        self.assertFalse(alive(dead.pid))
        self.write_pidfile({'pid': dead.pid, 'argv': [sys.executable, '-c', 'pass']})
        proxy = self.proxy()
        with proxy:
            self.assertEqual(proxy.reaped, 'stale_pidfile_removed')
            self.assertEqual(json.loads(self.pidfile().read_text())['pid'], proxy.started_pid)
        self.assertFalse(self.pidfile().exists())

    # --- failures ------------------------------------------------------------

    def test_proxy_exiting_before_ready_fails_and_leaves_nothing(self):
        proxy = self.proxy(flyctl=self.script('flyctl-exits', EXITS_AT_ONCE))
        with self.assertRaisesRegex(ProxyFailed, 'exited'):
            with proxy:
                self.fail('the context body must not run')
        self.assertIsNone(proxy.proc)
        self.assertIsNotNone(proxy.started_pid)
        self.assertFalse(alive(proxy.started_pid))
        self.assertFalse(self.pidfile().exists())

    def test_proxy_that_never_answers_is_stopped(self):
        proxy = self.proxy(flyctl=self.script('flyctl-hangs', NEVER_ANSWERS))
        with patch.object(fly_proxy, 'READY_ATTEMPTS', 3):
            with self.assertRaisesRegex(ProxyFailed, 'did not answer'):
                with proxy:
                    self.fail('the context body must not run')
        self.assertFalse(alive(proxy.started_pid))
        self.assertFalse(self.pidfile().exists())

    def test_stop_refuses_a_process_it_did_not_start(self):
        proxy = self.proxy()
        proxy.start()
        original = proxy.proc
        self.addCleanup(lambda: (original.poll() is None and original.terminate(), original.wait()))
        other = self.spawn([sys.executable, '-c', 'import time; time.sleep(60)'])
        proxy.proc = other
        with self.assertRaisesRegex(RuntimeError, 'did not start'):
            proxy.stop()
        self.assert_survives(other)
        # Its own pidfile is not cleaned up on a refused stop either.
        self.assertEqual(json.loads(self.pidfile().read_text())['pid'], original.pid)

    def test_stop_refuses_a_popen_like_object_without_calling_it(self):
        calls = []

        class Impostor:
            pid = os.getpid()

            def __getattr__(self, name):
                calls.append(name)
                return lambda *a, **k: calls.append((name, a, k))
        proxy = self.proxy()
        proxy.start()
        original = proxy.proc
        self.addCleanup(lambda: (original.poll() is None and original.terminate(), original.wait()))
        proxy.proc = Impostor()
        with self.assertRaises(RuntimeError):
            proxy.stop()
        self.assertEqual(calls, [])

    def test_job_name_must_be_an_identifier(self):
        for job in ('bad-job', '../escape', '', 'a b', 'x/y', '1st'):
            with self.subTest(job=job), self.assertRaisesRegex(ValueError, 'identifier'):
                FlyProxy(APP, self.state, job, flyctl=self.flyctl)
        self.assertEqual(FlyProxy(APP, self.state, 'monitor').pidfile.name, 'fly-proxy-monitor.json')


if __name__ == '__main__':
    unittest.main()
