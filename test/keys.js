// أدوات مشتركة للاختبارات: مفتاح RS256 حقيقي يُولَّد في الاختبار، وتوقيع
// رمز به. لا شبكة ولا حزمة خارجية.

const ALGO = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };

export function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function encodeJson(value) {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

export async function makeKey(kid) {
  const pair = await crypto.subtle.generateKey(
    { ...ALGO, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['sign', 'verify'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { pair, jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', kid } };
}

export async function sign(privateKey, header, payload) {
  const input = `${encodeJson(header)}.${encodeJson(payload)}`;
  const sig = await crypto.subtle.sign(ALGO, privateKey, new TextEncoder().encode(input));
  return `${input}.${b64url(new Uint8Array(sig))}`;
}

export function fakeKV() {
  const store = new Map();
  return {
    store,
    puts: [],
    async get(key, type) {
      const value = store.get(key);
      if (value === undefined) return null;
      return type === 'json' ? JSON.parse(value) : value;
    },
    async put(key, value, options) {
      store.set(key, value);
      this.puts.push({ key, value, options });
    },
    async delete(key) {
      store.delete(key);
    },
  };
}
