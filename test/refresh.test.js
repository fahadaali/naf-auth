// التجديد الصامت: رمزٌ انتهى عمره وفي الجلسة رمزُ تجديد يُجدَّد من المركز
// خادماً لخادم، فلا تحويلة ولا ٤٠١ — وما يرفضه المركز يُنهي الجلسة.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createConfig } from '../src/index.js';
import { authenticate } from '../src/middleware.js';
import { handleCallback } from '../src/callback.js';
import { sessionLifetime } from '../src/refresh.js';
import { sha256Hex, sessionKeyFor, userIndexKeyFor } from '../src/safe.js';
import { fakeKV, makeKey, sign } from './keys.js';

const ISSUER = 'https://id.naf.example';
const PLATFORM = 'naf-test';
const MEMBER = { id: 'u1', role: 'admin', is_active: 1, perms: null };

let KEY;
async function key() {
  if (!KEY) KEY = await makeKey('k1');
  return KEY;
}

async function token(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  const k = await key();
  return sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, {
    sub: 'u1', email: 'f@example.com', iss: ISSUER, aud: PLATFORM, iat: now, exp: now + 900, ...over,
  });
}

function setup() {
  const kv = fakeKV();
  const db = {
    prepare() {
      return { bind() { return this; }, async first() { return MEMBER; }, async run() { return {}; } };
    },
  };
  const env = { AUTH_ISSUER: ISSUER, PLATFORM_ID: PLATFORM, AUTH_CLIENT_SECRET: 's', AUTH_KV: kv, DB: db };
  return { kv, env, config: createConfig(env) };
}

async function withFetch(handlers, fn) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const href = String(url);
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url: href, body });
    if (href.endsWith('/.well-known/jwks.json')) return Response.json({ keys: [(await key()).jwk] });
    for (const [suffix, handler] of Object.entries(handlers)) {
      if (href.endsWith(suffix)) return handler(body);
    }
    return new Response('not found', { status: 404 });
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

const apiReq = (cookie) =>
  new Request('https://platform.example/api/stats', { headers: { cookie, 'sec-fetch-mode': 'cors' } });

async function expiredSession(kv, extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  const old = await token({ iat: now - 2000, exp: now - 1000 });
  await kv.put(await sessionKeyFor('s1'), JSON.stringify({ sub: 'u1', token: old, exp: now - 1000, ...extra }));
  await kv.put(await userIndexKeyFor('u1', 's1'), '1');
}

test('رمزٌ منتهٍ ومعه رمز تجديد: يُجدَّد خادماً لخادم ويمضي الطلب بلا ٤٠١', async () => {
  const { kv, env, config } = setup();
  await expiredSession(kv, { refresh: 'r'.repeat(43), remember: true });

  const fresh = await token();
  await withFetch(
    { '/api/refresh': () => Response.json({ token: fresh, expiresIn: 900, refreshExpiresIn: 7776000, remember: true }) },
    async (calls) => {
      const { user, response } = await authenticate(apiReq('naf_sid=s1'), env, config);
      assert.equal(response, undefined);
      assert.equal(user.id, 'u1');

      const call = calls.find((c) => c.url.endsWith('/api/refresh'));
      assert.deepEqual(call.body, { platformId: PLATFORM, secret: 's', refresh: 'r'.repeat(43) });
    },
  );

  const stored = await kv.get(await sessionKeyFor('s1'), 'json');
  assert.equal(stored.token, fresh);
  assert.equal(stored.refresh, 'r'.repeat(43));
  // الجلسة والدليل يُمدّان معاً إلى عمر جلسة المركز.
  const puts = kv.puts.filter((p) => p.options?.expirationTtl === 7776000).map((p) => p.key);
  assert.ok(puts.includes(await sessionKeyFor('s1')));
  assert.ok(puts.includes(await userIndexKeyFor('u1', 's1')));
});

test('المركز يرفض التجديد: تُمحى الجلسة ويأخذ النداء ٤٠١ كما كان', async () => {
  const { kv, env, config } = setup();
  await expiredSession(kv, { refresh: 'r'.repeat(43) });

  await withFetch({ '/api/refresh': () => Response.json({ error: 'invalid_grant' }, { status: 400 }) }, async () => {
    const { response } = await authenticate(apiReq('naf_sid=s1'), env, config);
    assert.equal(response.status, 401);
  });
  assert.equal(await kv.get(await sessionKeyFor('s1')), null);
  assert.equal(await kv.get(await userIndexKeyFor('u1', 's1')), null);
});

test('الحساب موقوف مركزياً (٤٠٣): تُمحى الجلسة', async () => {
  const { kv, env, config } = setup();
  await expiredSession(kv, { refresh: 'r'.repeat(43) });
  await withFetch({ '/api/refresh': () => Response.json({ error: 'access_denied' }, { status: 403 }) }, async () => {
    const { response } = await authenticate(apiReq('naf_sid=s1'), env, config);
    assert.equal(response.status, 401);
  });
  assert.equal(await kv.get(await sessionKeyFor('s1')), null);
});

test('المركز متعثّر: ٥٠٣ والجلسة باقية — لا يُعاقَب العضو بعطل الشبكة', async () => {
  const { kv, env, config } = setup();
  await expiredSession(kv, { refresh: 'r'.repeat(43) });
  await withFetch({ '/api/refresh': () => new Response('down', { status: 502 }) }, async () => {
    const { response } = await authenticate(apiReq('naf_sid=s1'), env, config);
    assert.equal(response.status, 503);
  });
  assert.notEqual(await kv.get(await sessionKeyFor('s1')), null);
});

test('جلسة قديمة بلا رمز تجديد: السلوك القديم — تُمحى ويعود الطلب إلى المركز', async () => {
  const { kv, env, config } = setup();
  await expiredSession(kv);
  await withFetch({}, async (calls) => {
    const { response } = await authenticate(apiReq('naf_sid=s1'), env, config);
    assert.equal(response.status, 401);
    assert.equal(calls.some((c) => c.url.endsWith('/api/refresh')), false);
  });
});

test('عمر الجلسة: مع «تذكّرني» كوكيٌّ طويل، وبدونه كوكيُّ جلسة تصفّح، وبلا تجديدٍ عمرُ الرمز', () => {
  const now = Math.floor(Date.now() / 1000);
  const remembered = sessionLifetime({ exp: now + 900, refresh: 'x', refreshExpiresIn: 7776000, remember: true });
  assert.equal(remembered.ttl, 7776000);
  assert.ok(remembered.cookieMaxAge >= 7776000);

  const brief = sessionLifetime({ exp: now + 900, refresh: 'x', refreshExpiresIn: 40000, remember: false });
  assert.equal(brief.ttl, 40000);
  assert.equal(brief.cookieMaxAge, null);

  const legacy = sessionLifetime({ exp: now + 900, refresh: null, refreshExpiresIn: NaN, remember: false });
  assert.ok(legacy.ttl <= 900 && legacy.ttl >= 899);
  assert.equal(legacy.cookieMaxAge, legacy.ttl);
});

test('الاستقبال يحفظ رمز التجديد في الجلسة لا في الكوكي، ويضع كوكيّاً طويلاً مع «تذكّرني»', async () => {
  const { kv, env, config } = setup();
  const nonce = 'bind-nonce';
  const bind = await sha256Hex(nonce);
  await withFetch(
    {
      '/api/token': async () =>
        Response.json({ token: await token(), next: '/', bind, refresh: 'R'.repeat(43), refreshExpiresIn: 7776000, remember: true }),
      '/api/internal/access': () => Response.json({ ok: true }),
    },
    async () => {
      const res = await handleCallback(
        new Request('https://platform.example/auth/callback?code=c&state=s', { headers: { cookie: `naf_sid_bind=${nonce}` } }),
        env,
        config,
      );
      assert.equal(res.status, 302);
      const cookies = res.headers.getSetCookie();
      const session = cookies.find((c) => c.startsWith('naf_sid='));
      assert.match(session, /Max-Age=\d{8,}/);
      assert.equal(session.includes('R'.repeat(43)), false);
    },
  );
  const record = [...kv.store.entries()].find(([k]) => k.startsWith('sess:'));
  assert.equal(JSON.parse(record[1]).refresh, 'R'.repeat(43));
});
