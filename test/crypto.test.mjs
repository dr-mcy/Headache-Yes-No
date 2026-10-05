// hyn-crypto.js のテスト。復号側はこのテスト内に独立に実装する (方式の仕様どおりか確認するため)。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const H = createRequire(import.meta.url)('../hyn-crypto.js');
const subtle = globalThis.crypto.subtle;
const INFO = 'headache-inbox-relay/v1';

async function genKeyPair() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  return { pub: await subtle.exportKey('jwk', kp.publicKey), priv: await subtle.exportKey('jwk', kp.privateKey) };
}

async function decrypt(privJwk, env) {
  const priv = await subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const epkRaw = H.fromB64u(env.epk);
  const epk = await subtle.importKey('raw', epkRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const bits = await subtle.deriveBits({ name: 'ECDH', public: epk }, priv, 256);
  const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: epkRaw, info: new TextEncoder().encode(INFO) },
    hk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: H.fromB64u(env.iv), additionalData: new TextEncoder().encode(INFO) }, key, H.fromB64u(env.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

const payload = { text: '頭痛チェックシート\n記入日: 2026/10/05\n氏名: 架空 太郎\n【備考】 絵文字😀と"引用符"', sentAt: '2026-10-05T01:02:03.000Z' };

test('round trip: 暗号化した内容を秘密鍵で復号できる', async () => {
  const { pub, priv } = await genKeyPair();
  const env = await H.encryptEnvelope(pub, payload);
  assert.deepEqual(Object.keys(env).sort(), ['ct', 'epk', 'iv', 'v']);
  assert.equal(env.v, 1);
  assert.equal(H.fromB64u(env.epk).length, 65);
  assert.equal(H.fromB64u(env.epk)[0], 4);
  assert.equal(H.fromB64u(env.iv).length, 12);
  assert.deepEqual(await decrypt(priv, env), payload);
});

test('平文は出力に含まれない', async () => {
  const { pub } = await genKeyPair();
  const env = await H.encryptEnvelope(pub, payload);
  const s = JSON.stringify(env);
  assert.ok(!s.includes('架空'));
  assert.ok(!Buffer.from(H.fromB64u(env.ct)).toString('utf8').includes('架空'));
});

test('送信ごとに epk / iv / ct が変わる (使い捨て鍵)', async () => {
  const { pub } = await genKeyPair();
  const a = await H.encryptEnvelope(pub, payload), b = await H.encryptEnvelope(pub, payload);
  assert.notEqual(a.epk, b.epk); assert.notEqual(a.iv, b.iv); assert.notEqual(a.ct, b.ct);
});

test('GCM: 暗号文・iv・epk の改ざんは復号に失敗する', async () => {
  const { pub, priv } = await genKeyPair();
  const env = await H.encryptEnvelope(pub, payload);
  const flip = (b64) => { const u = H.fromB64u(b64); u[u.length - 1] ^= 1; return H.toB64u(u); };
  await assert.rejects(decrypt(priv, { ...env, ct: flip(env.ct) }));
  await assert.rejects(decrypt(priv, { ...env, iv: flip(env.iv) }));
  const other = await H.encryptEnvelope(pub, payload);
  await assert.rejects(decrypt(priv, { ...env, epk: other.epk }));
});

test('別の鍵では復号できない', async () => {
  const a = await genKeyPair(), b = await genKeyPair();
  const env = await H.encryptEnvelope(a.pub, payload);
  await assert.rejects(decrypt(b.priv, env));
});

test('公開鍵に秘密鍵 d が混ざっていたら暗号化を拒否する', async () => {
  const { priv } = await genKeyPair();
  await assert.rejects(H.encryptEnvelope(priv, payload), /秘密鍵/);
});

test('公開鍵が不正なら拒否する', async () => {
  await assert.rejects(H.encryptEnvelope(null, payload));
  await assert.rejects(H.encryptEnvelope({ kty: 'RSA' }, payload));
});

test('base64url の往復', () => {
  const u = new Uint8Array(300).map((_, i) => i % 256);
  assert.deepEqual([...H.fromB64u(H.toB64u(u))], [...u]);
  assert.ok(!/[+/=]/.test(H.toB64u(u)));
});
