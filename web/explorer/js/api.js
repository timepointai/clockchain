// The /public/v1 client. Every call returns `{status, text, json}`: the exact
// response text is kept because the verifier checks the bytes that were
// served, not a re-encoding of them.
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
    const f = (path) => get(`${fixture}/${path}`);
    return {
      mode: 'fixture',
      health: () => f('health.json'),
      snapshot: () => f('snapshot.json'),
      subject: (id, asOf = null) => (asOf ? notRecorded() : f(`subjects/${id}.json`)),
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
