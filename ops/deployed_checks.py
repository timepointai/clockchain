#!/usr/bin/env python3
"""HTTP acceptance against a deployed image. Production only replays genuine media.

CC_SMOKE_ENTITY must name an entity with an admitted image. No claim is minted.
The isolated container lane prepares its own synthetic attachment separately.
"""
import base64
import copy
import hashlib
import json
import os
import time
import urllib.error
import urllib.request


# Replaying a genuine attachment uploads the whole image. Production media runs
# to megabytes over whatever link the operator is on, and thirty seconds was not
# enough for it: the first production run died writing the body, not waiting on
# a verdict. Overridable for a slower link still.
TIMEOUT = int(os.environ.get('CC_CHECK_TIMEOUT', '120'))

# A body small enough to finish writing before the node can answer. The node
# checks credentials before it reads the payload and then closes the
# connection, which is correct — it owes an unauthorized caller nothing, least
# of all megabytes of buffering — but it means a large body races the refusal
# and surfaces as a broken pipe rather than a status. Authorization is supposed
# to precede validation, so a minimal body tests that ordering more honestly
# than a valid one: if the node ever validated first, this would come back 400
# instead of 401 or 403 and the check would fail, which is the point.
DENIAL_PROBE = {'manifest': {}, 'author': '', 'signature': '', 'image_base64': ''}


def request(base, path, key=None, payload=None):
    headers = {'Authorization': 'Bearer ' + key} if key else {}
    data = None
    if payload is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def check(base, revision, entity, key, read_key):
    if not key or not read_key or key == read_key:
        raise ValueError('Distinct full and read-only credentials required')
    results = []

    def expect(name, path, credential, status, payload=None):
        actual, body = request(base, path, credential, payload)
        if actual != status:
            raise AssertionError(f'{name}: HTTP {actual}, expected {status}')
        results.append(name)
        return body

    health = json.loads(expect('build', '/health', None, 200))
    assert health['build'] == revision[:12], 'wrong deployed revision'
    assert health['posture'] == 'live', 'unexpected posture'
    before = json.loads(expect('deep health', '/health/deep', read_key, 200))
    path = f'/v1/entities/{entity}'
    expect('anonymous denied', path + '?as_of=0', None, 401)
    expect('wrong credential denied', path + '?as_of=0', 'invalid-credential', 401)
    expect('coordinate required', path, read_key, 400)
    now = int(time.time()) - 946728000
    expect('entity readable', path + f'?as_of={now}', read_key, 200)
    image_path = f'/v1/images?entity_id={entity}&as_of={now}'
    catalog = json.loads(expect('media readable', image_path, read_key, 200))
    current = [x for x in catalog['images'] if x['source_binding'] == 'currently_projected']
    assert current, 'canary entity has no current genuine media attachment'
    item = current[0]
    raw = expect('PNG readable', '/v1/images/' + item['manifest']['image_sha256'], read_key, 200)
    assert hashlib.sha256(raw).hexdigest() == item['manifest']['image_sha256']
    payload = {k: item[k] for k in ('manifest', 'author', 'signature')}
    payload['image_base64'] = base64.b64encode(raw).decode()
    replay = json.loads(expect('signed replay', '/v1/images', key, 201, payload))
    assert replay['appended'] == 'existing'
    assert replay['attachment_id'] == item['attachment_id']
    assert replay['historical_ledger_event'] is False
    expect('anonymous write denied', '/v1/images', None, 401, DENIAL_PROBE)
    expect('read-only write denied', '/v1/images', read_key, 403, DENIAL_PROBE)
    altered = copy.deepcopy(payload)
    altered['signature'] = '00' * 64
    expect('invalid signature denied', '/v1/images', key, 400, altered)
    altered = copy.deepcopy(payload)
    altered['image_base64'] = base64.b64encode(raw + b'corrupt').decode()
    expect('corrupt PNG denied', '/v1/images', key, 400, altered)
    altered = copy.deepcopy(payload)
    altered['manifest']['model_revision'] = 'unpinned'
    expect('unpinned model denied', '/v1/images', key, 400, altered)
    after = json.loads(expect('deep health after', '/health/deep', read_key, 200))
    assert before['media']['image_attachment_count'] == after['media']['image_attachment_count']
    assert before['event_count'] == after['event_count'], 'ledger changed during media-only checks'
    return {'revision': revision, 'attachment_id': item['attachment_id'], 'checks': results, 'result': 'pass'}


if __name__ == '__main__':
    result = check(os.environ['CC_NODE_URL'].rstrip('/'), os.environ['CC_RELEASE_SHA'],
                   os.environ['CC_SMOKE_ENTITY'], os.environ['CC_NODE_API_KEY'],
                   os.environ['CC_NODE_READ_KEY'])
    print(json.dumps(result, indent=2))
