// POST /api/submit  body: {v:1, epk, iv, ct}（端末内で暗号化済み）→ Redis に暗号文だけ積む。平文は受け取らない。
import {
  MAX_BODY_BYTES, ITEM_TTL_SECONDS, MAX_QUEUE, QUEUE_KEY, ITEM_PREFIX,
  json, redisConfig, redisPipeline, validateEnvelope, clientIp, rateKey, newId,
} from '../lib/relay.mjs';

const LIMIT_PER_HOUR = () => Math.max(1, parseInt(process.env.RATE_LIMIT_PER_HOUR || '30', 10) || 30);

export default {
  async fetch(request) {
    if (request.method !== 'POST') return json(405, { ok: false, error: 'POST only' }, { allow: 'POST' });
    const cfg = redisConfig();
    if (!cfg) return json(503, { ok: false, error: 'storage not configured' });

    if (!/^application\/json\b/i.test(request.headers.get('content-type') || '')) {
      return json(415, { ok: false, error: 'content-type must be application/json' });
    }
    const declared = parseInt(request.headers.get('content-length') || '0', 10);
    if (declared > MAX_BODY_BYTES) return json(413, { ok: false, error: 'too large' });
    const raw = await request.text();
    if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) return json(413, { ok: false, error: 'too large' });

    let body;
    try { body = JSON.parse(raw); } catch (e) { return json(400, { ok: false, error: 'invalid json' }); }
    const bad = validateEnvelope(body);
    if (bad) return json(400, { ok: false, error: bad });

    const now = Date.now();
    try {
      // レート制限: IP(ハッシュ) × 1 時間ごとの回数
      const rk = rateKey(clientIp(request), now);
      const [count] = await redisPipeline(cfg, [['INCR', rk], ['EXPIRE', rk, 7200]]);
      if (count > LIMIT_PER_HOUR()) return json(429, { ok: false, error: 'rate limited' }, { 'retry-after': '3600' });

      // 古い未取得分の掃除 + 上限確認
      const [, size] = await redisPipeline(cfg, [
        ['ZREMRANGEBYSCORE', QUEUE_KEY, '-inf', now - ITEM_TTL_SECONDS * 1000],
        ['ZCARD', QUEUE_KEY],
      ]);
      if (size >= MAX_QUEUE) return json(503, { ok: false, error: 'queue full' });

      const id = newId();
      const item = { id, receivedAt: new Date(now).toISOString(), epk: body.epk, iv: body.iv, ct: body.ct };
      await redisPipeline(cfg, [
        ['SET', ITEM_PREFIX + id, JSON.stringify(item), 'EX', ITEM_TTL_SECONDS],
        ['ZADD', QUEUE_KEY, now, id],
      ]);
      return json(200, { ok: true, id });
    } catch (e) {
      console.error('submit failed:', e && e.message);
      return json(502, { ok: false, error: 'storage error' });
    }
  },
};
