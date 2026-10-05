/* 平岸脳神経への送信用: 端末内での暗号化 (WebCrypto のみ・依存なし)。
 *
 * 方式 (v1): 院内の ECDH P-256 公開鍵 + 使い捨て ECDH 鍵 → HKDF-SHA256 → AES-256-GCM
 *   - 送信のたびに使い捨ての ECDH P-256 鍵対 (epk) を作り、院内公開鍵との共有秘密を求める
 *   - HKDF-SHA256: salt = epk(65 byte の非圧縮点), info = "headache-inbox-relay/v1" → 256 bit
 *   - AES-256-GCM: iv = 12 byte 乱数, additionalData = info
 *   - 平文 = UTF-8 の JSON {text, sentAt}
 *   - 出力 = { v:1, epk, iv, ct } (すべて base64url。ct は GCM タグ 16 byte を末尾に含む)
 * 復号は院内 (headache-inbox-relay) だけが秘密鍵で行う。サーバー(Vercel/Redis)は暗号文しか持たない。
 *
 * ブラウザでは window.HynCrypto、Node (テスト) では require() で使える。
 */
(function (root) {
  'use strict';
  var INFO = 'headache-inbox-relay/v1';
  var VERSION = 1;

  function getCrypto() {
    var c = (typeof globalThis !== 'undefined' && globalThis.crypto) || root.crypto;
    if (!c || !c.subtle) throw new Error('WebCrypto が使えません');
    return c;
  }

  function toB64u(bytes) {
    var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    var s = '';
    for (var i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64u(str) {
    var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // 公開鍵 JWK として使ってよいか (秘密鍵 d が混ざっていたら拒否する)
  function checkPublicJwk(jwk) {
    if (!jwk || typeof jwk !== 'object' || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
      throw new Error('公開鍵の形式が正しくありません');
    }
    if (jwk.d) throw new Error('秘密鍵が含まれています');
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true };
  }

  async function deriveAesKey(sharedBits, saltBytes, usage) {
    var subtle = getCrypto().subtle;
    var hkdfKey = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: new TextEncoder().encode(INFO) },
      hkdfKey, { name: 'AES-GCM', length: 256 }, false, [usage]);
  }

  // payload (JSON 化できるもの) を暗号化して { v, epk, iv, ct } を返す。
  async function encryptEnvelope(publicJwk, payload) {
    var c = getCrypto(), subtle = c.subtle;
    var pub = checkPublicJwk(publicJwk);
    var recipient = await subtle.importKey('jwk', pub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    var eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    var shared = await subtle.deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256);
    var epkRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
    var key = await deriveAesKey(shared, epkRaw, 'encrypt');
    var iv = c.getRandomValues(new Uint8Array(12));
    var plain = new TextEncoder().encode(JSON.stringify(payload));
    var ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: iv, additionalData: new TextEncoder().encode(INFO) }, key, plain));
    return { v: VERSION, epk: toB64u(epkRaw), iv: toB64u(iv), ct: toB64u(ct) };
  }

  var api = { VERSION: VERSION, INFO: INFO, encryptEnvelope: encryptEnvelope, toB64u: toB64u, fromB64u: fromB64u, checkPublicJwk: checkPublicJwk };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.HynCrypto = api;
})(typeof window !== 'undefined' ? window : this);
