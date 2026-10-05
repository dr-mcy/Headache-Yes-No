// GET /api/pull?limit=50  Authorization: Bearer <PULL_TOKEN>
// 院内の headache-inbox-relay だけが呼ぶ。未取得の暗号文を古い順に返す (削除は /api/ack)。
import { json, redisConfig, redisPipeline, checkBearer, QUEUE_KEY, ITEM_PREFIX } from '../lib/relay.mjs';

export default {
  async fetch(request) {
    if (request.method !== 'GET') return json(405, { ok: false, error: 'GET only' }, { allow: 'GET' });
    const auth = checkBearer(request);
    if (auth === 'not-configured') return json(503, { ok: false, error: 'PULL_TOKEN not configured' });
    if (auth !== 'ok') return json(401, { ok: false, error: 'unauthorized' }, { 'www-authenticate': 'Bearer' });
    const cfg = redisConfig();
    if (!cfg) return json(503, { ok: false, error: 'storage not configured' });

    const url = new URL(request.url);
    const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10) || 50));
    try {
      const [ids] = await redisPipeline(cfg, [['ZRANGE', QUEUE_KEY, 0, limit - 1]]);
      if (!ids.length) return json(200, { ok: true, items: [] });
      const [values] = await redisPipeline(cfg, [['MGET'].concat(ids.map((i) => ITEM_PREFIX + i))]);
      const items = [], expired = [];
      ids.forEach((id, i) => {
        if (values[i] == null) { expired.push(id); return; } // TTL で消えた分
        try { items.push(JSON.parse(values[i])); } catch (e) { expired.push(id); }
      });
      if (expired.length) await redisPipeline(cfg, [['ZREM', QUEUE_KEY].concat(expired)]);
      return json(200, { ok: true, items });
    } catch (e) {
      console.error('pull failed:', e && e.message);
      return json(502, { ok: false, error: 'storage error' });
    }
  },
};
