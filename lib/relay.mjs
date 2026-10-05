// 暗号文の中継 (api/submit, api/pull, api/ack) 共通部。依存なし。
// 保存するのは暗号文 {id, receivedAt, epk, iv, ct} だけ。平文・氏名などはここを通らない。
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const MAX_BODY_BYTES = 16 * 1024;
export const ITEM_TTL_SECONDS = 14 * 24 * 3600; // 14 日で自動消去
export const MAX_QUEUE = 3000;                 // 未取得の上限
export const QUEUE_KEY = 'hyn:q';              // sorted set (score = 受信 ms, member = id)
export const ITEM_PREFIX = 'hyn:item:';        // 暗号文本体 (TTL 付き)
export const RATE_PREFIX = 'hyn:rl:';

export function json(status, obj, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    }, extraHeaders || {}),
  });
}

// Vercel Marketplace の Upstash Redis 連携が入れる環境変数。
// 公式 Marketplace 版 (KV 互換) は KV_REST_API_URL / KV_REST_API_TOKEN、
// Upstash 直の連携は UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN。どちらでも動くようにする。
export function redisConfig(env) {
  env = env || process.env;
  const url = env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL;
  const token = env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return { url: url.replace(/\/+$/, ''), token };
}

// Upstash REST の pipeline: POST <url>/pipeline、本文は [[cmd, ...args], ...]、応答は [{result}|{error}, ...]
export async function redisPipeline(cfg, commands) {
  const res = await fetch(cfg.url + '/pipeline', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + cfg.token, 'content-type': 'application/json' },
    body: JSON.stringify(commands),
  });
  if (!res.ok) throw new Error('redis http ' + res.status);
  const out = await res.json();
  if (!Array.isArray(out) || out.length !== commands.length) throw new Error('redis bad response');
  for (const r of out) if (r && r.error) throw new Error('redis error: ' + r.error);
  return out.map((r) => r.result);
}

const B64U = /^[A-Za-z0-9_-]+$/;
function b64uLen(s) { // base64url 文字列がデコードで何 byte になるか (不正なら -1)
  if (typeof s !== 'string' || !B64U.test(s) || s.length % 4 === 1) return -1;
  return Math.floor(s.length * 3 / 4);
}

// {v:1, epk, iv, ct} だけを通す。epk=65 byte(非圧縮点 0x04…)、iv=12 byte、ct=17 byte 以上〜上限。
export function validateEnvelope(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return '形式が正しくありません';
  const keys = Object.keys(obj).sort().join(',');
  if (keys !== 'ct,epk,iv,v') return '項目が正しくありません';
  if (obj.v !== 1) return '版が正しくありません';
  if (b64uLen(obj.epk) !== 65 || obj.epk[0] !== 'B') return 'epk が正しくありません'; // 0x04 始まり = base64url の先頭 'B'
  if (b64uLen(obj.iv) !== 12) return 'iv が正しくありません';
  const n = b64uLen(obj.ct);
  if (n < 17 || n > 14000) return 'ct の大きさが正しくありません';
  return null;
}

function sha256(s) { return createHash('sha256').update(s).digest(); }

export function checkBearer(request, env) {
  env = env || process.env;
  const expected = env.PULL_TOKEN;
  if (!expected) return 'not-configured';
  const m = /^Bearer (.+)$/.exec(request.headers.get('authorization') || '');
  if (!m) return 'unauthorized';
  return timingSafeEqual(sha256(m[1]), sha256(expected)) ? 'ok' : 'unauthorized';
}

export function clientIp(request) {
  // Vercel は x-forwarded-for を上書きするため、先頭を送信元として使う
  const xff = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || '';
  return xff.split(',')[0].trim() || 'unknown';
}

export function rateKey(ip, nowMs) {
  const hour = Math.floor(nowMs / 3600000);
  return RATE_PREFIX + createHash('sha256').update(ip).digest('hex').slice(0, 24) + ':' + hour;
}

export function newId() { return randomBytes(8).toString('hex'); }
export function isId(s) { return typeof s === 'string' && /^[0-9a-f]{16}$/.test(s); }
