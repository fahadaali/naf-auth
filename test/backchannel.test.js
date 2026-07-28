// إشعار الخروج الخلفي — المركز يُنهي جلسات عضوٍ في هذه المنصة.
//
// الحال التي وُجد لها: الخروج من منصةٍ محليّ عمداً، أمّا الخروج من المركز
// فهو الباب نفسه. وبلا هذا الإشعار تبقى جلسة كل منصة حيّة حتى ينتهي رمزها،
// فيفتح صاحبُها رابط المنصة بعد خروجه من المركز فيدخل.
//
// وأخطر ما يُحرَس هنا ليس المسار السويّ بل تمييزُ النوع: المركز يوقّع رمز
// الدخول ورمز الإشعار بالمفتاح نفسه ولنفس الجمهور، والإشعار يصل إلى مسار
// عامّ لا حراسة عليه. فلولا التمييز صلح أن يُقدَّم كرمز جلسة.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createConfig, LOGOUT_PURPOSE } from '../src/index.js';
import { handleBackchannelLogout } from '../src/logout.js';
import { authenticate } from '../src/middleware.js';
import { fakeKV, makeKey, sign } from './keys.js';

const ISSUER = 'https://id.naf.example';
const PLATFORM = 'naf-test';

let KEY;
async function key() {
  if (!KEY) KEY = await makeKey('k1');
  return KEY;
}

function setup() {
  const kv = fakeKV();
  const env = {
    AUTH_ISSUER: ISSUER,
    PLATFORM_ID: PLATFORM,
    AUTH_CLIENT_SECRET: 's',
    AUTH_KV: kv,
    DB: {
      prepare: () => ({
        bind() {
          return this;
        },
        async first() {
          return { id: 'u1', role: 'admin', is_active: 1, perms: null };
        },
        async run() {
          return { success: true };
        },
      }),
    },
  };
  return { kv, env, config: createConfig(env) };
}

async function signed(over = {}) {
  const k = await key();
  const now = Math.floor(Date.now() / 1000);
  return sign(
    k.pair.privateKey,
    { alg: 'RS256', kid: 'k1' },
    { sub: 'u1', iss: ISSUER, aud: PLATFORM, iat: now, exp: now + 60, ...over },
  );
}

const logoutToken = (over = {}) => signed({ purpose: LOGOUT_PURPOSE, ...over });

function jwks(kv, jwk) {
  // مفتاح الخبيئة كما تكتبه الحزمة — لا شبكة في هذه الاختبارات.
  kv.store.set(`jwks:${ISSUER}`, JSON.stringify({ keys: [jwk] }));
}

function post(body) {
  return new Request(`https://naf-test.example/auth/backchannel-logout`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** جلسة كاملة: المفتاح ودليلُه، كما يكتبهما مسار الاستقبال. */
async function seedSession(kv, sid, sub = 'u1') {
  await kv.put(`sess:${sid}`, JSON.stringify({ sub, token: 't', exp: 0 }));
  await kv.put(`usr:${sub}:${sid}`, '1');
}

test('الإشعار يُنهي كل جلسات العضو ودليلَها', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  await seedSession(kv, 's1');
  await seedSession(kv, 's2');
  await seedSession(kv, 's3'); // ثلاث جلسات على صفحاتٍ من صفحتين — فالمؤشّر يُستعمل

  const res = await handleBackchannelLogout(post({ logoutToken: await logoutToken() }), env, config);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, ended: 3 });
  for (const sid of ['s1', 's2', 's3']) {
    assert.equal(kv.store.has(`sess:${sid}`), false, `الجلسة ${sid} بقيت`);
    assert.equal(kv.store.has(`usr:u1:${sid}`), false, `دليل ${sid} بقي`);
  }
});

test('ولا يمسّ جلسات غيره', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  await seedSession(kv, 's1', 'u1');
  await seedSession(kv, 's9', 'u2');

  await handleBackchannelLogout(post({ logoutToken: await logoutToken() }), env, config);

  assert.equal(kv.store.has('sess:s1'), false);
  assert.equal(kv.store.has('sess:s9'), true, 'خروج فلان أخرج غيره');
});

test('وبعده لا تفتح الجلسة الممحوّة شيئاً', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  await seedSession(kv, 's1');

  await handleBackchannelLogout(post({ logoutToken: await logoutToken() }), env, config);

  const { response, user } = await authenticate(
    new Request('https://naf-test.example/', { headers: { cookie: 'naf_sid=s1' } }),
    env,
    config,
  );
  assert.equal(user, undefined);
  assert.equal(response.status, 302);
  assert.match(response.headers.get('location'), new RegExp(`^${ISSUER}/go/`));
});

// ─────────── ما يُردّ ───────────

test('رمز الدخول لا يصلح إشعار خروج', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  await seedSession(kv, 's1');

  // رمز جلسةٍ صحيح تماماً — توقيعاً و`iss` و`aud` — لكنه بلا `purpose`.
  const res = await handleBackchannelLogout(post({ logoutToken: await signed() }), env, config);

  assert.equal(res.status, 401);
  assert.equal(kv.store.has('sess:s1'), true, 'رمز جلسة أنهى جلسة');
});

test('وإشعار الخروج لا يصلح رمز جلسة', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  // الإشعار يصل إلى مسار عامّ، فمن التقطه لو قُبل جلسةً لدخل به.
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: await logoutToken(), exp: 0 }));

  const { response, user } = await authenticate(
    new Request('https://naf-test.example/', { headers: { cookie: 'naf_sid=s1' } }),
    env,
    config,
  );
  assert.equal(user, undefined);
  assert.equal(response.status, 302);
});

test('إشعارٌ لمنصة أخرى يُردّ بـ aud', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  await seedSession(kv, 's1');

  const res = await handleBackchannelLogout(
    post({ logoutToken: await logoutToken({ aud: 'naf-other' }) }),
    env,
    config,
  );
  assert.equal(res.status, 401);
  assert.equal(kv.store.has('sess:s1'), true);
});

test('وإشعارٌ بتوقيع مفتاحٍ آخر يُردّ', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk); // المنصة تعرف k1

  const forger = await makeKey('k1'); // المعرّف نفسه، مفتاحٌ آخر
  const now = Math.floor(Date.now() / 1000);
  const forged = await sign(
    forger.pair.privateKey,
    { alg: 'RS256', kid: 'k1' },
    { sub: 'u1', iss: ISSUER, aud: PLATFORM, iat: now, exp: now + 60, purpose: LOGOUT_PURPOSE },
  );
  await seedSession(kv, 's1');

  const res = await handleBackchannelLogout(post({ logoutToken: forged }), env, config);
  assert.equal(res.status, 401);
  assert.equal(kv.store.has('sess:s1'), true);
});

test('وإشعارٌ منتهٍ يُردّ', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  await seedSession(kv, 's1');
  const now = Math.floor(Date.now() / 1000);

  const res = await handleBackchannelLogout(
    post({ logoutToken: await logoutToken({ iat: now - 600, exp: now - 300 }) }),
    env,
    config,
  );
  assert.equal(res.status, 401);
  assert.equal(kv.store.has('sess:s1'), true);
});

test('وجسمٌ بلا رمز يُردّ ٤٠٠', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  const res = await handleBackchannelLogout(post({}), env, config);
  assert.equal(res.status, 400);
});

test('وطريقةٌ غير POST تُردّ ٤٠٥', async () => {
  const { env, config } = setup();
  const res = await handleBackchannelLogout(
    new Request('https://naf-test.example/auth/backchannel-logout'),
    env,
    config,
  );
  assert.equal(res.status, 405);
  assert.equal(res.headers.get('allow'), 'POST');
});

test('وعضوٌ لا جلسة له هنا: صفرٌ لا خطأ', async () => {
  const { kv, env, config } = setup();
  jwks(kv, (await key()).jwk);
  // المركز ينادي الخمس جميعاً ولا يعرف أيّها دخل صاحبُ الخروج.
  const res = await handleBackchannelLogout(post({ logoutToken: await logoutToken() }), env, config);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, ended: 0 });
});
