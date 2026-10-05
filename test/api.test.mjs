// api/submit, api/pull, api/ack のテスト。Redis は test/fake-upstash.mjs (Upstash REST の最小モック)。架空データのみ。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { startFakeUpstash } from './fake-upstash.mjs';

const H = createRequire(import.meta.url)('../hyn-crypto.js');
const subtle = globalThis.crypto.subtle;

async function envelope(text = '頭痛チェックシート\n記入日: 2026/10/05\n氏名: 架空 太郎') {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  return H.encryptEnvelope(await subtle.exportKey('jwk', kp.publicKey), { text, sentAt: '2026-10-05T01:02:03.000Z' });
}

function req(method, path, { body, headers, ip } = {}) {
  const h = { 'content-type': 'application/json', 'x-forwarded-for': ip || '203.0.113.7', ...(headers || {}) };
  return new Request('https://example.test' + path, { method, headers: h, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)) });
}

async function setup(env = {}) {
  const redis = await startFakeUpstash();
  const saved = { ...process.env };
  Object.assign(process.env, { KV_REST_API_URL: redis.url, KV_REST_API_TOKEN: redis.token, PULL_TOKEN: 'pull-secret', ...env });
  delete process.env.UPSTASH_REDIS_REST_URL; delete process.env.UPSTASH_REDIS_REST_TOKEN;
  // 毎回新しい module instance を使う必要は無い (環境変数は呼び出しごとに読む)
  const submit = (await import('../api/submit.mjs')).default, pull = (await import('../api/pull.mjs')).default, ack = (await import('../api/ack.mjs')).default;
  return {
    redis, submit, pull, ack,
    async done() { await redis.close(); for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]; Object.assign(process.env, saved); },
  };
}
const bearer = (t = 'pull-secret') => ({ authorization: 'Bearer ' + t });

test('submit: 正常な暗号文を受け付け、受付番号を返し、Redis には暗号文だけが入る', async () => {
  const t = await setup();
  try {
    const env = await envelope();
    const res = await t.submit.fetch(req('POST', '/api/submit', { body: env }));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true); assert.match(body.id, /^[0-9a-f]{16}$/);
    const stored = [...t.redis.kv.entries()];
    assert.equal(stored.length, 1);
    assert.ok(stored[0][0].startsWith('hyn:item:'));
    assert.equal(stored[0][1].ttl, 14 * 24 * 3600);
    const item = JSON.parse(stored[0][1].v);
    assert.deepEqual(Object.keys(item).sort(), ['ct', 'epk', 'id', 'iv', 'receivedAt']);
    assert.equal(item.ct, env.ct);
    assert.ok(!stored[0][1].v.includes('架空'));
    assert.equal(t.redis.zsets.get('hyn:q').size, 1);
    // レート制限のキーに生 IP を使わない
    assert.ok(![...t.redis.counters.keys()].some((k) => k.includes('203.0.113.7')));
  } finally { await t.done(); }
});

test('submit: スキーマ違反は 400 (保存しない)', async () => {
  const t = await setup();
  try {
    const env = await envelope();
    const cases = [
      { ...env, v: 2 }, { ...env, extra: 1 }, { epk: env.epk, iv: env.iv, v: 1 },
      { ...env, epk: env.epk.slice(1) }, { ...env, iv: 'AAAA' }, { ...env, ct: 'AAAA' },
      { ...env, ct: 'a+b/' + env.ct }, { ...env, text: '平文' }, [env], 'x', null,
    ];
    for (const c of cases) {
      const res = await t.submit.fetch(req('POST', '/api/submit', { body: c === null ? 'null' : c }));
      assert.equal(res.status, 400, JSON.stringify(c).slice(0, 60));
    }
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: '{bad' }))).status, 400);
    assert.equal(t.redis.kv.size, 0);
  } finally { await t.done(); }
});

test('submit: 16KB 超は 413、Content-Type 違いは 415、GET は 405', async () => {
  const t = await setup();
  try {
    const env = await envelope();
    const big = { ...env, ct: 'A'.repeat(17000) };
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: big }))).status, 413);
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: env, headers: { 'content-type': 'text/plain' } }))).status, 415);
    assert.equal((await t.submit.fetch(req('GET', '/api/submit'))).status, 405);
    assert.equal(t.redis.kv.size, 0);
  } finally { await t.done(); }
});

test('submit: IP ごとのレート制限 (超過は 429、別 IP は通る)', async () => {
  const t = await setup({ RATE_LIMIT_PER_HOUR: '3' });
  try {
    const env = await envelope();
    const st = [];
    for (let i = 0; i < 5; i++) st.push((await t.submit.fetch(req('POST', '/api/submit', { body: env, ip: '198.51.100.1' }))).status);
    assert.deepEqual(st, [200, 200, 200, 429, 429]);
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: env, ip: '198.51.100.2' }))).status, 200);
    assert.equal(t.redis.kv.size, 4);
  } finally { await t.done(); }
});

test('submit: Redis 未設定は 503、Redis 障害は 502', async () => {
  const t = await setup();
  try {
    const env = await envelope();
    const saved = { u: process.env.KV_REST_API_URL, k: process.env.KV_REST_API_TOKEN };
    delete process.env.KV_REST_API_URL; delete process.env.KV_REST_API_TOKEN;
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: env }))).status, 503);
    process.env.KV_REST_API_URL = saved.u; process.env.KV_REST_API_TOKEN = 'wrong';
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: env }))).status, 502);
  } finally { await t.done(); }
});

test('submit: UPSTASH_REDIS_REST_* の環境変数名でも動く', async () => {
  const t = await setup();
  try {
    process.env.UPSTASH_REDIS_REST_URL = process.env.KV_REST_API_URL; process.env.UPSTASH_REDIS_REST_TOKEN = process.env.KV_REST_API_TOKEN;
    delete process.env.KV_REST_API_URL; delete process.env.KV_REST_API_TOKEN;
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: await envelope() }))).status, 200);
  } finally { await t.done(); }
});

test('submit: キュー上限に達したら 503', async () => {
  const t = await setup();
  try {
    const q = new Map(); for (let i = 0; i < 3000; i++) q.set('x' + i, Date.now()); t.redis.zsets.set('hyn:q', q);
    assert.equal((await t.submit.fetch(req('POST', '/api/submit', { body: await envelope() }))).status, 503);
  } finally { await t.done(); }
});

test('pull/ack: Bearer 必須 (無し/違いは 401、PULL_TOKEN 未設定は 503)', async () => {
  const t = await setup();
  try {
    assert.equal((await t.pull.fetch(req('GET', '/api/pull'))).status, 401);
    assert.equal((await t.pull.fetch(req('GET', '/api/pull', { headers: bearer('nope') }))).status, 401);
    assert.equal((await t.ack.fetch(req('POST', '/api/ack', { body: { ids: ['0123456789abcdef'] } }))).status, 401);
    assert.equal((await t.pull.fetch(req('GET', '/api/pull', { headers: bearer() }))).status, 200);
    delete process.env.PULL_TOKEN;
    assert.equal((await t.pull.fetch(req('GET', '/api/pull', { headers: bearer() }))).status, 503);
    assert.equal((await t.ack.fetch(req('POST', '/api/ack', { headers: bearer(), body: { ids: ['0123456789abcdef'] } }))).status, 503);
  } finally { await t.done(); }
});

test('pull → ack: 古い順に返し、ack した分だけ消える', async () => {
  const t = await setup();
  try {
    const ids = [];
    for (let i = 0; i < 3; i++) ids.push((await (await t.submit.fetch(req('POST', '/api/submit', { body: await envelope('頭痛チェックシート\n記入日: 2026/10/0' + (i + 1)), ip: '192.0.2.' + i }))).json()).id);
    const r1 = await (await t.pull.fetch(req('GET', '/api/pull?limit=2', { headers: bearer() }))).json();
    assert.deepEqual(r1.items.map((x) => x.id), ids.slice(0, 2));
    assert.deepEqual(Object.keys(r1.items[0]).sort(), ['ct', 'epk', 'id', 'iv', 'receivedAt']);
    const a = await (await t.ack.fetch(req('POST', '/api/ack', { headers: bearer(), body: { ids: [ids[0]] } }))).json();
    assert.deepEqual(a, { ok: true, removed: 1 });
    const r2 = await (await t.pull.fetch(req('GET', '/api/pull', { headers: bearer() }))).json();
    assert.deepEqual(r2.items.map((x) => x.id), ids.slice(1));
    assert.ok(!t.redis.kv.has('hyn:item:' + ids[0]));
  } finally { await t.done(); }
});

test('pull: TTL で消えた分はキューからも掃除される', async () => {
  const t = await setup();
  try {
    const id = (await (await t.submit.fetch(req('POST', '/api/submit', { body: await envelope() }))).json()).id;
    t.redis.kv.delete('hyn:item:' + id);
    const r = await (await t.pull.fetch(req('GET', '/api/pull', { headers: bearer() }))).json();
    assert.deepEqual(r.items, []);
    assert.equal(t.redis.zsets.get('hyn:q').size, 0);
  } finally { await t.done(); }
});

test('ack: ids の形式が不正なら 400', async () => {
  const t = await setup();
  try {
    for (const ids of [[], ['zz'], 'abc', [1], Array(101).fill('0123456789abcdef'), ['0123456789abcdef", "x']]) {
      assert.equal((await t.ack.fetch(req('POST', '/api/ack', { headers: bearer(), body: { ids } }))).status, 400);
    }
  } finally { await t.done(); }
});
