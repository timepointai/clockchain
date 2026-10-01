"""Stage (e) adapter: model expectations for explicit symbolic traces.

Reads a JSON list of traces (event dicts as emitted by projection_oracle) on
stdin and prints, for each, the unchanged `model.fold` projection of every
subset mask. Stdlib only; the accepted model/checker bytes are not modified.
"""
import json
import sys
from model import Event
from projection_oracle import projection

traces = json.load(sys.stdin)
out = []
for events in traces:
    events = [Event(e['id'], e['kind'], e['key'], e['grant'], tuple(e['parents']),
                    e['target'], e['cascade']) for e in events]
    out.append([dict(mask=m, expected=projection([e for e in events if m & (1 << e.id)]))
                for m in range(1 << len(events))])
print(json.dumps(out, separators=(',', ':')))
