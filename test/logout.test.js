// اختبارات الخروج، والوجهة المعلّقة على باب المركز، والصلاحية في التبليغ.
//
// العطل الذي تحرسه هذه الملفّات: الخروج كان يعيد المستخدم إلى `‎/` — وهو
// محميّ — فيحوّله الوسيط إلى المركز، وجلسة المركز قائمة، فيعود إلى الشاشة
// التي خرج منها. زرٌّ يعمل ولا يظهر أثره.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createConfig } from '../src/index.js';
import { authenticate } from '../src/middleware.js';
import { handleLogout, logoutTarget } from '../src/logout.js';
import { reportAccessChange } from '../src/callback.js';
import { fakeKV } from './keys.js';

const ISSUER = 'https://id.naf.example';
const PLATFORM = 'naf-test';

function setup({ secret = 'sh-secret' } = {}) {
  const kv = fakeKV();
  const env = {
    AUTH_ISSUER: `${ISSUER}/`, // بشرطة أخيرة عمداً — تُوحَّد عند بناء الإعداد
    PLATFORM_ID: PLATFORM,
    AUTH_CLIENT_SECRET: secret,
    AUTH_KV: kv,
  };
  return { kv, env, config: createConfig(env) };
}

const reqWith = (path, { cookie, mode, accept, method = 'GET' } = {}) => {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (mode) headers['sec-fetch-mode'] = mode;
  if (accept) headers.accept = accept;
  return new Request(`https://platform.example${path}`, { method, headers });
};

// ───────────────────────────── الخروج ─────────────────────────────

test('الوجهة بعد الخروج هي المركز لا جذر المنصة', () => {
  const { config } = setup();
  // شرطةٌ واحدة لا اثنتان: `AUTH_ISSUER` وصل بشرطة أخيرة وقد وُحّد.
  assert.equal(logoutTarget(config), `${ISSUER}/`);
});

test('تنقّلٌ للخروج: ٣٠٢ إلى المركز، والكوكي ممسوح، والجلسة محذوفة', async () => {
  const { kv, env, config } = setup();
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: 't', exp: 0 }));

  const response = await handleLogout(
    reqWith('/auth/logout', { cookie: 'naf_sid=s1', mode: 'navigate' }),
    env,
    config,
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), `${ISSUER}/`);
  assert.match(response.headers.get('set-cookie'), /naf_sid=;/);
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  // الحذف من KV هو الخروج فعلاً: الكوكي الممسوح يبقى صالحاً عند من نسخه.
  assert.equal(await kv.get('sess:s1'), null);
});

test('نداء fetch للخروج: ٢٠٠ ومعه الوجهة نصّاً لا تحويلة', async () => {
  const { kv, env, config } = setup();
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: 't', exp: 0 }));

  const response = await handleLogout(
    reqWith('/auth/logout', { cookie: 'naf_sid=s1', mode: 'cors', method: 'POST' }),
    env,
    config,
  );

  // المتصفّح لا يتبع تحويلةً إلى أصل آخر في fetch — فتُعطى الوجهة لتنتقل
  // إليها اللوحة بنفسها.
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.equal(body.next, `${ISSUER}/`);
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal(await kv.get('sess:s1'), null);
});

test('الخروج بجلسة منتهية أصلاً ينجح ولا يرمي', async () => {
  const { env, config } = setup();
  // من انتهت جلسته يجب أن يخرج كذلك — النتيجة المطلوبة تحقّقت.
  const response = await handleLogout(
    reqWith('/auth/logout', { mode: 'navigate' }),
    env,
    config,
  );
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), `${ISSUER}/`);
});

test('تعذّر حذف المفتاح لا يمنع الخروج', async () => {
  const { env, config } = setup();
  const seen = [];
  config.onError = (code) => seen.push(code);
  config.kv = () => ({
    async delete() {
      throw new Error('KV down');
    },
  });

  const response = await handleLogout(
    reqWith('/auth/logout', { cookie: 'naf_sid=s1', mode: 'navigate' }),
    env,
    config,
  );

  assert.equal(response.status, 302);
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  assert.deepEqual(seen, ['logout_delete_failed']);
});

// ─────────────── الوجهة المعلّقة على باب المركز ───────────────

test('الوجهة تُعلَّق للتنقّل وحده لا لنداء برمجي', async () => {
  const { env, config } = setup();

  const nav = await authenticate(reqWith('/posts?page=2', { mode: 'navigate' }), env, config);
  const navNext = new URL(nav.response.headers.get('location')).searchParams.get('next');
  assert.equal(navNext, '/posts?page=2');

  // مسارُ نداءٍ برمجي لا يصلح وجهةَ عودة: العودة إليه بعد الدخول تعرض JSON
  // خاماً مكان اللوحة. والمتصفّح وحده يعرف الصفحة التي يقف فيها صاحبها.
  const api = await authenticate(reqWith('/api/me', { mode: 'cors' }), env, config);
  assert.equal(api.response.status, 401);
  const login = new URL((await api.response.json()).login);
  assert.equal(login.searchParams.has('next'), false);
  assert.equal(login.pathname, `/go/${PLATFORM}`);
});

// ─────────────── الصلاحية في التبليغ العكسي ───────────────

async function withAccessFetch(fn) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), body: init.body ? JSON.parse(init.body) : null });
    return Response.json({ ok: true });
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

test('التبليغ يحمل الصلاحية مع الحالة', async () => {
  const { env, config } = setup();
  await withAccessFetch(async (calls) => {
    await reportAccessChange(env, config, {
      email: ' F@Example.com ',
      state: 'granted',
      role: ' admin ',
    });
    assert.equal(calls[0].url, `${ISSUER}/api/internal/access`);
    assert.equal(calls[0].body.email, 'F@Example.com');
    assert.equal(calls[0].body.state, 'granted');
    assert.equal(calls[0].body.role, 'admin');
    // المنصة تبلّغ عن نفسها لا عن غيرها.
    assert.equal(calls[0].body.platformId, PLATFORM);
  });
});

test('تبليغ صلاحية وحدها لا يحمل حالة، فلا يمسّ المنح', async () => {
  const { env, config } = setup();
  await withAccessFetch(async (calls) => {
    await reportAccessChange(env, config, { email: 'f@example.com', role: 'viewer' });
    assert.equal('state' in calls[0].body, false);
    assert.equal(calls[0].body.role, 'viewer');
  });
});

test('تبليغ بلا حالة ولا صلاحية يُمنع قبل أن يحمل السرّ', async () => {
  const { env, config } = setup();
  await withAccessFetch(async (calls) => {
    await assert.rejects(
      () => reportAccessChange(env, config, { email: 'f@example.com' }),
      (err) => err.code === 'empty_access_report',
    );
    assert.equal(calls.length, 0);
  });
});

test('حالة غير مقبولة تُمنع قبل أن يحمل السرّ', async () => {
  const { env, config } = setup();
  await withAccessFetch(async (calls) => {
    await assert.rejects(
      () => reportAccessChange(env, config, { email: 'f@example.com', state: 'paused' }),
      (err) => err.code === 'bad_access_state',
    );
    assert.equal(calls.length, 0);
  });
});

// ─────────── مسار الاستقبال ليس وجهةً ───────────

test('بلوغ مسار الاستقبال بلا رمز يبدأ الدخول بوجهة الجذر لا بنفسه', async () => {
  const { env, config } = setup();
  const { handleCallback } = await import('../src/callback.js');

  const response = await handleCallback(
    reqWith('/auth/callback', { mode: 'navigate' }),
    env,
    config,
  );

  assert.equal(response.status, 302);
  const target = new URL(response.headers.get('location'));
  assert.equal(target.pathname, `/go/${PLATFORM}`);
  /* لو حملت `next=/auth/callback` لدارت دورة لا تنتهي: المركز يعيد الرمز
     إلى هذا المسار، فتتمّ المبادلة، ثم يُحوَّل إلى `next` أي إليه بلا رمز،
     فيبدأ الدخول من أوّله. والمتصفّح يقطعها بـERR_TOO_MANY_REDIRECTS. */
  assert.equal(target.searchParams.has('next'), false);
});
