// Upstash Redis REST (/pipeline) の最小モック。api/*.mjs が使うコマンドだけ実装する (テスト専用)。
import http from 'node:http';

export function startFakeUpstash(token = 'test-redis-token') {
  const kv = new Map();      // key -> { v, ttl }
  const zsets = new Map();   // key -> Map(member -> score)
  const counters = new Map();
  const log = [];
  const z = (k) => { if (!zsets.has(k)) zsets.set(k, new Map()); return zsets.get(k); };

  function exec(cmd) {
    const [name, ...a] = cmd; log.push(cmd);
    switch (String(name).toUpperCase()) {
      case 'INCR': { const n = (counters.get(a[0]) || 0) + 1; counters.set(a[0], n); return n; }
      case 'EXPIRE': return 1;
      case 'SET': { const ex = a.indexOf('EX'); kv.set(a[0], { v: a[1], ttl: ex >= 0 ? Number(a[ex + 1]) : null }); return 'OK'; }
      case 'MGET': return a.map((k) => (kv.has(k) ? kv.get(k).v : null));
      case 'DEL': { let n = 0; a.forEach((k) => { if (kv.delete(k)) n++; }); return n; }
      case 'ZADD': { const s = z(a[0]); const had = s.has(a[2]); s.set(a[2], Number(a[1])); return had ? 0 : 1; }
      case 'ZCARD': return z(a[0]).size;
      case 'ZRANGE': {
        const arr = [...z(a[0]).entries()].sort((x, y) => x[1] - y[1] || (x[0] < y[0] ? -1 : 1)).map((e) => e[0]);
        const stop = Number(a[2]); return arr.slice(Number(a[1]), stop < 0 ? undefined : stop + 1);
      }
      case 'ZREM': { const s = z(a[0]); let n = 0; a.slice(1).forEach((m) => { if (s.delete(m)) n++; }); return n; }
      case 'ZREMRANGEBYSCORE': {
        const s = z(a[0]); const lo = a[1] === '-inf' ? -Infinity : Number(a[1]); const hi = Number(a[2]); let n = 0;
        for (const [m, sc] of [...s]) if (sc >= lo && sc <= hi) { s.delete(m); n++; }
        return n;
      }
      default: throw new Error('ERR unknown command ' + name);
    }
  }

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (req.headers.authorization !== 'Bearer ' + token) { res.writeHead(401); res.end('{"error":"unauthorized"}'); return; }
      try {
        const cmds = JSON.parse(body);
        const out = req.url === '/pipeline' ? cmds.map((c) => { try { return { result: exec(c) }; } catch (e) { return { error: e.message }; } }) : { result: exec(cmds) };
        res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(out));
      } catch (e) { res.writeHead(400); res.end(JSON.stringify({ error: e.message })); }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: 'http://127.0.0.1:' + server.address().port, token, kv, zsets, counters, log,
    close: () => new Promise((r) => server.close(r)),
  })));
}
