"""Private, human-selected model routes. Discovery never changes the selection."""
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError('duplicate JSON key')
            result[k] = v
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def save(path, value, *, replace=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = canonical(value) + b'\n'
    if replace:
        import tempfile
        fd, temp = tempfile.mkstemp(prefix='.write-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, path)
        finally:
            if os.path.exists(temp): os.unlink(temp)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def private(path):
    path = Path(path).expanduser().resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError('private operational artifacts must be outside the checkout')
    return path


def utc():
    return datetime.now(timezone.utc).isoformat()


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timezone required')
    return result


def exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError('invalid contract fields: ' + fields)


def nonempty(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('nonempty text required')


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('integer outside bounds')


def amount(value):
    if isinstance(value, bool): raise ValueError('invalid monetary amount')
    v = Decimal(str(value))
    if not v.is_finite() or v < 0:
        raise ValueError('invalid monetary amount')
    return v


def micro(value):
    return int((amount(value) * 1_000_000).to_integral_value(rounding=ROUND_CEILING))


def evidence(item):
    exact(item, 'url path sha256')
    if not item['url'].startswith('https://') or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
        raise ValueError('invalid evidence reference')
    if digest(Path(item['path']).read_bytes()) != item['sha256']:
        raise ValueError('reviewed evidence changed')


def validate_route(route):
    exact(route, 'schema id adapter model provider provider_slug endpoint_name quantization hosted_weight_digest settings prices rights evaluation')
    if route['schema'] != 'cc.model-route.v1' or route['adapter'] != 'openrouter-chat':
        raise ValueError('unsupported route/adapter; requires explicit implementation and qualification')
    if not re.fullmatch('[a-z0-9][a-z0-9._-]{0,100}', route['id']):
        raise ValueError('invalid route id')
    for k in ('model', 'provider', 'provider_slug', 'endpoint_name', 'quantization'): nonempty(route[k])
    if route['hosted_weight_digest'] is not None and not re.fullmatch('[0-9a-f]{64}', route['hosted_weight_digest']):
        raise ValueError('invalid model digest')
    settings = route['settings']
    exact(settings, 'reasoning temperature top_p max_tokens deadline_seconds')
    reasoning = settings['reasoning']
    if not isinstance(reasoning, dict) or not ((set(reasoning) == {'enabled'} and type(reasoning['enabled']) is bool) or
            (set(reasoning) == {'effort'} and reasoning['effort'] in ('none', 'minimal', 'low', 'medium', 'high', 'xhigh'))):
        raise ValueError('invalid reasoning configuration')
    if not 0 <= amount(settings['temperature']) <= 2 or not 0 < amount(settings['top_p']) <= 1:
        raise ValueError('invalid sampling configuration')
    integer(settings['max_tokens'], 128, 64000)
    integer(settings['deadline_seconds'], 10, 1200)
    exact(route['prices'], 'prompt_per_million_usd completion_per_million_usd')
    for v in route['prices'].values(): amount(v)
    rights = route['rights']
    exact(rights, 'license_spdx commercial_use output_training reviewed_by reviewed_at expires_at model_license provider_terms router_terms conditions')
    if rights['license_spdx'] not in ('Apache-2.0', 'MIT') or rights['commercial_use'] is not True or rights['output_training'] is not True:
        raise ValueError('commercial output/training permission not reviewed')
    nonempty(rights['reviewed_by']); nonempty(rights['conditions'])
    now = datetime.now(timezone.utc)
    if not timestamp(rights['reviewed_at']) <= now < timestamp(rights['expires_at']):
        raise ValueError('rights review expired or not yet effective')
    for k in ('model_license', 'provider_terms', 'router_terms'): evidence(rights[k])
    exact(route['evaluation'], 'path sha256 scope')
    nonempty(route['evaluation']['scope'])
    if digest(Path(route['evaluation']['path']).read_bytes()) != route['evaluation']['sha256']:
        raise ValueError('evaluation evidence changed')
    return route


def choose(registry, route_path, chosen_by, reason, decision_reference):
    registry = private(registry); route_path = private(route_path)
    for s in (chosen_by, reason, decision_reference): nonempty(s)
    route = validate_route(read(route_path))
    registry.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (registry/'selection.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        receipt = {'schema':'cc.model-selection.v1', 'route_path':str(route_path),
                   'route_sha256':digest(route_path.read_bytes()), 'chosen_by':chosen_by,
                   'chosen_at':utc(), 'reason':reason, 'decision_reference':decision_reference,
                   'publication_authorized':False}
        ident = digest(canonical(receipt))
        save(registry/'selections'/(ident+'.json'), receipt)
        save(registry/'active.json', receipt, replace=True)
    return route['id'], ident


def selected(registry, expected=None):
    registry = private(registry)
    if (registry/'STOP').exists(): raise ValueError('model generation paused by STOP')
    selection = read(registry/'active.json')
    exact(selection, 'schema route_path route_sha256 chosen_by chosen_at reason decision_reference publication_authorized')
    if selection['schema'] != 'cc.model-selection.v1' or selection['publication_authorized'] is not False:
        raise ValueError('invalid human selection')
    for k in ('chosen_by', 'reason', 'decision_reference'): nonempty(selection[k])
    if timestamp(selection['chosen_at']) > datetime.now(timezone.utc): raise ValueError('future selection')
    ident = digest(canonical(selection))
    if read(registry/'selections'/(ident+'.json')) != selection:
        raise ValueError('selection receipt missing or changed')
    if expected is not None and expected != ident: raise ValueError('human model selection changed')
    route_path = private(selection['route_path'])
    if digest(route_path.read_bytes()) != selection['route_sha256']: raise ValueError('selected route changed')
    return validate_route(read(route_path)), ident


class Budget:
    """Single registry accounting, shared by concurrent local processes.

    Remote workers must use the same registry/SQLite filesystem. This is not a
    distributed accounting backend. Unknown outcomes retain their full hold.
    """
    def __init__(self, registry):
        self.root = private(registry)
        self.policy = read(self.root/'budget.json')
        exact(self.policy, 'schema total_limit_micro_usd daily_limit_micro_usd max_daily_calls')
        if self.policy['schema'] != 'cc.model-budget.v1': raise ValueError('invalid budget policy')
        for k in ('total_limit_micro_usd', 'daily_limit_micro_usd'): integer(self.policy[k], 0, 100_000_000)
        integer(self.policy['max_daily_calls'], 0, 1000)
        self.db = sqlite3.connect(self.root/'budget.sqlite3', timeout=30, isolation_level=None)
        (self.root/'budget.sqlite3').chmod(0o600)
        self.db.execute('CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, day TEXT NOT NULL, reserved INTEGER NOT NULL, actual INTEGER, settled_day TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS control (id INTEGER PRIMARY KEY CHECK(id=1), blocked INTEGER NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO control VALUES(1,0)')
    def reserve(self, ident, upper):
        integer(upper, 0, 100_000_000)
        day = utc()[:10]
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self.db.execute('SELECT blocked FROM control').fetchone()[0]: raise ValueError('budget frozen after price overrun')
            rows = self.db.execute('SELECT day,reserved,actual,settled_day FROM attempts').fetchall()
            total = sum(res if actual is None else actual for _,res,actual,_ in rows)
            daily = sum(res if actual is None else actual for _,res,actual,settled in rows if actual is None or settled == day)
            if total+upper > self.policy['total_limit_micro_usd'] or daily+upper > self.policy['daily_limit_micro_usd'] or sum(d==day for d,_,_,_ in rows) >= self.policy['max_daily_calls']:
                raise ValueError('model budget exhausted')
            self.db.execute('INSERT INTO attempts(id,day,reserved) VALUES(?,?,?)', (ident,day,upper))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise
    def settle(self, ident, cost):
        actual = micro(cost)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT reserved,actual FROM attempts WHERE id=?',(ident,)).fetchone()
            if row is None or row[1] is not None: raise ValueError('missing/already settled attempt')
            self.db.execute('UPDATE attempts SET actual=?,settled_day=? WHERE id=?',(actual,utc()[:10],ident))
            if actual > row[0]: self.db.execute('UPDATE control SET blocked=1')
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise
        if actual > row[0]: raise ValueError('reported charge exceeded reservation; budget frozen')
    def status(self):
        rows = self.db.execute('SELECT reserved,actual FROM attempts').fetchall()
        return {'calls':len(rows),'spent_micro_usd':sum(a for _,a in rows if a is not None),
                'held_micro_usd':sum(r for r,a in rows if a is None),
                'blocked':bool(self.db.execute('SELECT blocked FROM control').fetchone()[0])}
    def close(self): self.db.close()
