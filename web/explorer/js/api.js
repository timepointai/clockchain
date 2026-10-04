// The /public/v1 client. Every call returns `{status, ok, text, json}`. The
// response text is kept and handed to the verifier as served, so the values it
// checks are the values the page displays (it compares JSON values, not bytes).
//
// Fixture mode reads a recorded synthetic fixture instead of a gateway. It
// answers only the requests that were recorded; anything else is a 404 with
// `{"error": "not_recorded"}`, never an invented answer.

export function client({ base = '/public/v1', fixture = null, fetchImpl = globalThis.fetch } = {}) {
  const get = async (url) => {
    const r = await fetchImpl(url, { headers: { accept: 'application/json' } });
    const text = await r.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    return { status: r.status, ok: r.ok, text, json };
  };
  const notRecorded = () => ({ status: 404, ok: false, text: '{"error":"not_recorded"}', json: { error: 'not_recorded' } });
  const q = (params) => {
    const s = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== null && v !== undefined && v !== '')).toString();
    return s ? `?${s}` : '';
  };
  if (fixture !== null) {
    const f = async (path) => {
      const r = await get(`${fixture}/${path}`);
      return r.status === 404 ? notRecorded() : r;
    };
    return {
      mode: 'fixture',
      health: () => f('health.json'),
      snapshot: () => f('snapshot.json'),
      subject: (id, asOf = null) => f(asOf ? `subjects/${id}.as_of.${asOf}.json` : `subjects/${id}.json`),
      prose: (rev) => f(`revisions/${rev}/prose.json`),
      support: (from, to, asOf = null) => (asOf ? notRecorded() : f(`support/${from}-${to}.json`)),
      export: () => f('export.json'),
    };
  }
  return {
    mode: 'gateway',
    health: () => get(`${base}/health`),
    snapshot: () => get(`${base}/snapshot`),
    subject: (id, asOf = null) => get(`${base}/subjects/${id}${q({ as_of: asOf })}`),
    prose: (rev) => get(`${base}/revisions/${rev}/prose`),
    support: (from, to, asOf = null) => get(`${base}/support${q({ from, to, as_of: asOf })}`),
    // Not a /public/v1 route; the export is supplied by the user as a file.
    export: async () => notRecorded(),
  };
}
