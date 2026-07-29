// اختبارات التحقق من الرمز الموقّع — بمفتاح RS256 حقيقي يُولَّد في الاختبار،
// وبديل لـ fetch يحصي طلبات JWKS. لا شبكة ولا حزمة خارجية.

import test from 'node:test';
import assert from 'node:assert/strict';

import { verifyToken } from '../src/verify.js';

const ALGO = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function encodeJson(value) {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

async function makeKey(kid) {
  const pair = await crypto.subtle.generateKey(
    { ...ALGO, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['sign', 'verify'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { pair, jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', kid } };
}

async function sign(privateKey, header, payload) {
  const input = `${encodeJson(header)}.${encodeJson(payload)}`;
  const sig = await crypto.subtle.sign(ALGO, privateKey, new TextEncoder().encode(input));
  return `${input}.${b64url(new Uint8Array(sig))}`;
}

function fakeKV() {
  const store = new Map();
  return {
    store,
    async get(k, type) {
      const v = store.get(k);
      if (v === undefined) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(k, v) {
      store.set(k, v);
    },
    async delete(k) {
      store.delete(k);
    },
  };
}

const ISSUER = 'https://id.naf.example';
const PLATFORM = 'naf-test';

function setup(keys) {
  const kv = fakeKV();
  const calls = { jwks: 0 };
  const original = globalThis.fetch;

  globalThis.fetch = async () => {
    calls.jwks++;
    return new Response(JSON.stringify({ keys: keys.current }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  const config = {
    issuer: ISSUER,
    platformId: PLATFORM,
    kv: () => kv,
  };
  return { kv, calls, config, restore: () => { globalThis.fetch = original; } };
}

function claims(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { sub: 'u1', name: 'فهد', email: 'f@example.com', iss: ISSUER, aud: PLATFORM, iat: now, exp: now + 900, ...over };
}

test('رمز سليم يجتاز التحقق', async () => {
  const k = await makeKey('k1');
  const keys = { current: [k.jwk] };
  const { config, restore } = setup(keys);
  try {
    const token = await sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims());
    const payload = await verifyToken(token, {}, config);
    assert.equal(payload.sub, 'u1');
    assert.equal(payload.email, 'f@example.com');
  } finally {
    restore();
  }
});

test('المفاتيح تُكاش فلا تُجلب مرتين', async () => {
  const k = await makeKey('k1');
  const { config, calls, restore } = setup({ current: [k.jwk] });
  try {
    const token = await sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims());
    await verifyToken(token, {}, config);
    await verifyToken(token, {}, config);
    assert.equal(calls.jwks, 1);
  } finally {
    restore();
  }
});

test('معرّف مفتاح غير معروف يعيد الجلب فوراً بدل انتظار الكاش', async () => {
  const oldKey = await makeKey('k1');
  const newKey = await makeKey('k2');
  const keys = { current: [oldKey.jwk] };
  const { config, calls, kv, restore } = setup(keys);
  try {
    // يملأ الكاش بالمفتاح القديم
    await verifyToken(await sign(oldKey.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims()), {}, config);
    assert.equal(calls.jwks, 1);
    assert.ok(kv.store.has(`jwks:${ISSUER}`));

    // المركز يدوّر مفاتيحه
    keys.current = [newKey.jwk];
    const token = await sign(newKey.pair.privateKey, { alg: 'RS256', kid: 'k2' }, claims());
    const payload = await verifyToken(token, {}, config);

    assert.equal(payload.sub, 'u1');
    assert.equal(calls.jwks, 2, 'يجب إعادة الجلب عند kid غير معروف');
  } finally {
    restore();
  }
});

test('رمز منصة أخرى يُرفض بـ aud', async () => {
  const k = await makeKey('k1');
  const { config, restore } = setup({ current: [k.jwk] });
  try {
    const token = await sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims({ aud: 'naf-other' }));
    await assert.rejects(() => verifyToken(token, {}, config), (e) => e.code === 'bad_audience');
  } finally {
    restore();
  }
});

test('مُصدِر آخر يُرفض', async () => {
  const k = await makeKey('k1');
  const { config, restore } = setup({ current: [k.jwk] });
  try {
    const token = await sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims({ iss: 'https://evil.sa' }));
    await assert.rejects(() => verifyToken(token, {}, config), (e) => e.code === 'bad_issuer');
  } finally {
    restore();
  }
});

test('رمز منتهي الصلاحية يُرفض، وفارق الساعة لا يتجاوز ٦٠ ثانية', async () => {
  const k = await makeKey('k1');
  const { config, restore } = setup({ current: [k.jwk] });
  const now = Math.floor(Date.now() / 1000);
  try {
    const expired = await sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims({ exp: now - 120 }));
    await assert.rejects(() => verifyToken(expired, {}, config), (e) => e.code === 'token_expired');

    // داخل هامش الستين ثانية لا يزال مقبولاً
    const justExpired = await sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims({ exp: now - 30 }));
    assert.equal((await verifyToken(justExpired, {}, config)).sub, 'u1');
  } finally {
    restore();
  }
});

test('توقيع بمفتاح آخر يُرفض', async () => {
  const real = await makeKey('k1');
  const forger = await makeKey('k1');
  const { config, restore } = setup({ current: [real.jwk] });
  try {
    const token = await sign(forger.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims());
    await assert.rejects(() => verifyToken(token, {}, config), (e) => e.code === 'bad_signature');
  } finally {
    restore();
  }
});

test('خوارزمية غير RS256 تُرفض قبل أي عمل تعمية', async () => {
  const k = await makeKey('k1');
  const { config, calls, restore } = setup({ current: [k.jwk] });
  try {
    const payload = encodeJson(claims());
    for (const alg of ['none', 'HS256', 'RS512']) {
      const token = `${encodeJson({ alg, kid: 'k1' })}.${payload}.`;
      await assert.rejects(() => verifyToken(token, {}, config), (e) => e.code === 'bad_alg');
    }
    assert.equal(calls.jwks, 0, 'لا يُجلب أي مفتاح قبل ردّ الخوارزمية');
  } finally {
    restore();
  }
});

test('رمز مشوّه يُرفض', async () => {
  const { config, restore } = setup({ current: [] });
  try {
    for (const bad of ['', 'a.b', 'a.b.c.d', 'not-a-token', null]) {
      await assert.rejects(() => verifyToken(bad, {}, config), (e) => e.code === 'token_malformed');
    }
  } finally {
    restore();
  }
});

test('رمز بلا sub يُرفض', async () => {
  const k = await makeKey('k1');
  const { config, restore } = setup({ current: [k.jwk] });
  try {
    const token = await sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims({ sub: undefined }));
    await assert.rejects(() => verifyToken(token, {}, config), (e) => e.code === 'missing_sub');
  } finally {
    restore();
  }
});

test('شرطة مائلة أخيرة في AUTH_ISSUER لا ترفض الرمز', async () => {
  const k = await makeKey('k1');
  const { restore } = setup({ current: [k.jwk] });
  try {
    // `createConfig` يوحّد صورة المُصدِر مرة واحدة، فما يصل إلى المقارنة
    // موحَّد أصلاً — وهذا يعالج شرطةً كُتبت في wrangler.toml سهواً.
    const { createConfig } = await import('../src/index.js');
    const config = createConfig({
      AUTH_ISSUER: `${ISSUER}/`,
      PLATFORM_ID: PLATFORM,
      AUTH_KV: {},
      kv: () => {},
    }, { kv: () => setup({ current: [k.jwk] }).kv });
    assert.equal(config.issuer, ISSUER, 'الشرطة تُحذف عند بناء الإعداد');
  } finally {
    restore();
  }
});

test('المقارنة بعد التوحيد حرفية: iss بشرطة أخيرة من المركز يُرفض', async () => {
  const k = await makeKey('k1');
  const { config, restore } = setup({ current: [k.jwk] });
  try {
    // المُصدِر قيمةٌ موقّعة من المركز، وسير النشر هناك يفشل إن خالفت
    // النطاق الفعلي. فقبول صورةٍ أخرى منها توسيعٌ لا يقابله شيء في العقد.
    const token = await sign(
      k.pair.privateKey,
      { alg: 'RS256', kid: 'k1' },
      claims({ iss: `${ISSUER}/` }),
    );
    await assert.rejects(() => verifyToken(token, {}, config), (e) => e.code === 'bad_issuer');
  } finally {
    restore();
  }
});

test('مُصدِر مختلف فعلاً لا يزال يُرفض رغم التوحيد', async () => {
  const k = await makeKey('k1');
  const { config, restore } = setup({ current: [k.jwk] });
  try {
    const token = await sign(
      k.pair.privateKey,
      { alg: 'RS256', kid: 'k1' },
      claims({ iss: `${ISSUER}.evil.sa` }),
    );
    await assert.rejects(() => verifyToken(token, {}, config), (e) => e.code === 'bad_issuer');
  } finally {
    restore();
  }
});

// ───────── إعادة الجلب عند kid مجهول: تعمل، ولا تُضخِّم ─────────

test('kid مجهول يُجبر جلباً واحداً — فالتدوير لا يعطّل المنصة', async () => {
  const oldKey = await makeKey('k1');
  const newKey = await makeKey('k2');
  // المخبأ يحمل المفتاح القديم وحده، كما هي الحال لحظةَ التدوير.
  const s = setup({ current: [newKey.jwk] });
  try {
    await s.kv.put(`jwks:${ISSUER}`, JSON.stringify({ keys: [oldKey.jwk] }));

    const now = Math.floor(Date.now() / 1000);
    const token = await sign(newKey.pair.privateKey, { alg: 'RS256', kid: 'k2' }, {
      sub: 'u1', iss: ISSUER, aud: PLATFORM, iat: now, exp: now + 900,
    });

    const claims = await verifyToken(token, {}, s.config);
    assert.equal(claims.sub, 'u1', 'الرمز الموقّع بالمفتاح الجديد يمرّ');
    assert.equal(s.calls.jwks, 1, 'جلبٌ واحد لا أكثر');
  } finally {
    s.restore();
  }
});

test('سيلٌ من kid مجهول لا يُجبر إلا جلباً واحداً — لا تضخيم على المركز', async () => {
  /* `‎/auth/backchannel-logout` مسارٌ عامّ بلا مصادقة، ورمزٌ مركَّب بـkid
     عشوائي يبلغ موضعَ الجلب **قبل** التحقق من التوقيع. فبلا سقفٍ يصير كلُّ
     طلبٍ مزوَّر جلباً شبكياً إلى المركز وكتابةً في KV. */
  const key = await makeKey('k1');
  const s = setup({ current: [key.jwk] });
  try {
    await s.kv.put(`jwks:${ISSUER}`, JSON.stringify({ keys: [key.jwk] }));

    const now = Math.floor(Date.now() / 1000);
    for (let i = 0; i < 25; i++) {
      const forged = await sign(key.pair.privateKey, { alg: 'RS256', kid: `x${i}` }, {
        sub: 'u1', iss: ISSUER, aud: PLATFORM, iat: now, exp: now + 900,
      });
      await assert.rejects(() => verifyToken(forged, {}, s.config), /unknown_kid/);
    }

    assert.equal(s.calls.jwks, 1, `٢٥ طلباً مزوَّراً أنتجت ${s.calls.jwks} جلباً — يجب أن يكون واحداً`);
  } finally {
    s.restore();
  }
});
