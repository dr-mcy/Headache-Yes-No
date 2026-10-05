// POST /api/ack  body: {ids:[...]}  Authorization: Bearer <PULL_TOKEN>  → 取り込み済みの暗号文を削除
import { json, redisConfig, redisPipeline, checkBearer, isId, QUEUE_KEY, ITEM_PREFIX } from '../lib/relay.mjs';

export default {
  async fetch(request) {
    if (request.method !== 'POST') return json(405, { ok: false, error: 'POST only' }, { allow: 'POST' });
    const auth = checkBearer(request);
    if (auth === 'not-configured') return json(503, { ok: false, error: 'PULL_TOKEN not configured' });
    if (auth !== 'ok') return json(401, { ok: false, error: 'unauthorized' }, { 'www-authenticate': 'Bearer' });
    const cfg = redisConfig();
    if (!cfg) return json(503, { ok: false, error: 'storage not configured' });

    let body;
    try { body = JSON.parse(await request.text()); } catch (e) { return json(400, { ok: false, error: 'invalid json' }); }
    const ids = body && body.ids;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 100 || !ids.every(isId)) {
      return json(400, { ok: false, error: 'ids must be 1-100 ids' });
    }
    try {
      const [removed] = await redisPipeline(cfg, [
        ['ZREM', QUEUE_KEY].concat(ids),
        ['DEL'].concat(ids.map((i) => ITEM_PREFIX + i)),
      ]);
      return json(200, { ok: true, removed });
    } catch (e) {
      console.error('ack failed:', e && e.message);
      return json(502, { ok: false, error: 'storage error' });
    }
  },
};
