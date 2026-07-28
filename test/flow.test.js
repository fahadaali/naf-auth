// اختبارات التدفّق: الوسيط ومسار الاستقبال والتبليغ العكسي وجدول الأعضاء،
// على بدائل بسيطة لـ KV و D1 و fetch — بلا شبكة وبلا حزمة اختبار خارجية.
//
// والرموز موقّعة بمفتاح RS256 حقيقي يُولَّد في الاختبار، لأن الوسيط صار
// يتحقّق من التوقيع في كل طلب محمي — فجلسةٌ برمز وهمي لا تمرّ.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createConfig } from '../src/index.js';
import { authenticate, isPublicPath } from '../src/middleware.js';
import { handleCallback, reportAccessChange } from '../src/callback.js';
import { getMember, upsertMember } from '../src/store.js';
import { fakeKV, makeKey, sign } from './keys.js';

const ISSUER = 'https://id.naf.example';
const PLATFORM = 'naf-test';

function fakeDB(row = null) {
  const statements = [];
  return {
    statements,
    prepare(sql) {
      statements.push(sql);
      return {
        bind(...args) {
          this.args = args;
          return this;
        },
        async first() {
          return row;
        },
        async run() {
          return { success: true };
        },
      };
    },
  };
}

/** مفتاح واحد يخدم كل الاختبارات — توليده مكلف. */
let KEY;
async function key() {
  if (!KEY) KEY = await makeKey('k1');
  return KEY;
}

function claims(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: 'u1',
    name: 'فهد',
    email: 'f@example.com',
    iss: ISSUER,
    aud: PLATFORM,
    iat: now,
    exp: now + 900,
    ...over,
  };
}

async function token(over = {}) {
  const k = await key();
  return sign(k.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims(over));
}

/**
 * بديل `fetch` يخدم `JWKS` و `‎/api/token` و `‎/api/internal/access`،
 * ويسجّل كل طلب ليُفحص جسمه.
 */
async function withFetch(handlers, fn) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const href = String(url);
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ url: href, body });

    if (href.endsWith('/.well-known/jwks.json')) {
      const k = await key();
      return Response.json({ keys: [k.jwk] });
    }
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

function setup({ member = null, secret = 'sh-secret' } = {}) {
  const kv = fakeKV();
  const db = fakeDB(member);
  const env = {
    AUTH_ISSUER: ISSUER,
    PLATFORM_ID: PLATFORM,
    AUTH_CLIENT_SECRET: secret,
    AUTH_KV: kv,
    DB: db,
  };
  return { kv, db, env, config: createConfig(env) };
}

const req = (path, cookie) =>
  new Request(`https://platform.example${path}`, cookie ? { headers: { cookie } } : undefined);

/** طلب بترويسات: `mode` لـ`Sec-Fetch-Mode` و`accept` لترويسة القبول. */
const reqWith = (path, { cookie, mode, accept } = {}) => {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (mode) headers['sec-fetch-mode'] = mode;
  if (accept) headers.accept = accept;
  return new Request(`https://platform.example${path}`, { headers });
};

// ───────────────────────────── الحارس ─────────────────────────────

test('المسارات العامة مكتوبة صراحةً وما عداها محمي', () => {
  const { config } = setup();
  for (const path of ['/auth/callback', '/denied', '/health', '/assets/app.js']) {
    assert.equal(isPublicPath(path, config), true, `${path} يجب أن يكون عاماً`);
  }
  // أي مسار جديد محمي افتراضياً — بما فيه ما يشبه العام.
  for (const path of ['/', '/posts', '/admin', '/health-check', '/assets', '/denied-x']) {
    assert.equal(isPublicPath(path, config), false, `${path} يجب أن يكون محمياً`);
  }
});

test('بلا كوكي: تحويل إلى باب المركز ومعه الوجهة — وبلا حالة من طرفنا', async () => {
  const { env, config } = setup();
  const { response } = await authenticate(req('/posts?page=2'), env, config);

  assert.equal(response.status, 302);
  const location = new URL(response.headers.get('location'));
  assert.equal(location.origin + location.pathname, `${ISSUER}/go/${PLATFORM}`);
  assert.equal(location.searchParams.get('next'), '/posts?page=2');

  // `‎/go/:id` يتجاهل أي state يصله ويولّد واحدة من عنده، فإرسال واحدة
  // من هنا يوهم بمطابقة لا تقع.
  assert.equal(location.searchParams.has('state'), false);
});

test('طلب واجهة برمجية بلا جلسة يردّ ٤٠١ ومعه عنوان الباب لا تحويلة', async () => {
  const { env, config } = setup();
  const { response } = await authenticate(req('/api/stats'), env, config);

  assert.equal(response.status, 401);
  const body = await response.json();
  assert.equal(body.ok, false);
  assert.match(body.login, new RegExp(`^${ISSUER}/go/${PLATFORM}`));
});

test('وجهة خارجية لا تصل إلى المركز أصلاً', async () => {
  const { env, config } = setup();
  const { response } = await authenticate(req('/%2F%2Fevil.sa'), env, config);
  const next = new URL(response.headers.get('location')).searchParams.get('next');
  // فُكّ الترميز فآل إلى `//evil.sa`، فرُدّ إلى الجذر ولم يُرسل أصلاً.
  assert.equal(next, null);
});

test('جلسة منتهية تعود إلى المركز ولا تجدّد نفسها', async () => {
  const { env, config } = setup();
  const { response, user } = await authenticate(req('/posts', 'naf_sid=ghost'), env, config);
  assert.equal(user, undefined);
  assert.equal(response.status, 302);
  assert.match(response.headers.get('location'), new RegExp(`^${ISSUER}/go/`));
});

test('عضو موقوف محلياً يُرفض رغم رمزه الصالح', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'writer', is_active: 0, perms: null },
  });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: await token(), exp: 0 }));

  await withFetch({}, async () => {
    const { response, user } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);
    assert.equal(user, undefined);
    assert.equal(response.headers.get('location'), '/denied?r=inactive');
  });
});

test('عضو نشط برمز صالح يُحقن في السياق بدوره وصلاحياته', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'general_manager', is_active: 1, perms: '{"x":true}' },
  });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: await token(), exp: 0 }));

  await withFetch({}, async () => {
    const { user, response } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);
    assert.equal(response, undefined);
    assert.deepEqual(user, { id: 'u1', role: 'general_manager', perms: { x: true } });
  });
});

// ────────────── التحقق في كل طلب محمي لا عند الاستقبال وحده ──────────────

test('رمز الجلسة المنتهي يُبطل الجلسة ويعيد الطلب إلى المركز', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'admin', is_active: 1, perms: null },
  });
  const now = Math.floor(Date.now() / 1000);
  const stale = await token({ exp: now - 600 });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: stale, exp: now - 600 }));

  await withFetch({}, async () => {
    const { response, user } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);

    assert.equal(user, undefined, 'رمز منتهٍ يجب ألّا يمرّ ولو كان العضو نشطاً');
    assert.equal(response.status, 302);
    // الجلسة تُمسح فلا تُقرأ مرة أخرى.
    assert.equal(kv.store.has('sess:s1'), false);
  });
});

test('رمز موقّع بمفتاح آخر لا يمرّ ولو كانت الجلسة قائمة', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'admin', is_active: 1, perms: null },
  });
  const forger = await makeKey('k1');
  const forged = await sign(forger.pair.privateKey, { alg: 'RS256', kid: 'k1' }, claims());
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: forged, exp: 0 }));

  await withFetch({}, async () => {
    const { response, user } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);
    assert.equal(user, undefined);
    assert.equal(response.status, 302);
  });
});

test('رمز منصة أخرى في الجلسة يُرفض', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'admin', is_active: 1, perms: null },
  });
  await kv.put(
    'sess:s1',
    JSON.stringify({ sub: 'u1', token: await token({ aud: 'NAF-Forms' }), exp: 0 }),
  );

  await withFetch({}, async () => {
    const { user } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);
    assert.equal(user, undefined);
  });
});

// ───────────────────────────── الاستقبال ─────────────────────────────

test('الاستقبال بلا رمز يعيد التحويل إلى المركز', async () => {
  const { env, config } = setup();
  const res = await handleCallback(req('/auth/callback'), env, config);
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location'), new RegExp(`^${ISSUER}/go/`));
});

test('الاستقبال بلا حالة يُرفض', async () => {
  const { env, config } = setup();
  const res = await handleCallback(req('/auth/callback?code=c1'), env, config);
  assert.equal(res.headers.get('location'), '/denied?r=bad_state');
});

test('المبادلة ترسل الحقول الأربعة بأسماء المركز، والحالة كما وصلت', async () => {
  const { env, config } = setup({ member: { id: 'u1', role: 'admin', is_active: 1, perms: null } });

  await withFetch(
    { '/api/token': async () => Response.json({ token: await token(), tokenType: 'Bearer', expiresIn: 900, next: '/' }) },
    async (calls) => {
      await handleCallback(req('/auth/callback?code=c1&state=STATE-FROM-CENTER'), env, config);

      const exchange = calls.find((c) => c.url.endsWith('/api/token'));
      assert.ok(exchange, 'يجب أن تقع المبادلة');
      // أسماء الحقول حرفياً — أي اسم آخر يردّ عليه المركز invalid_body.
      assert.deepEqual(Object.keys(exchange.body).sort(), ['code', 'platformId', 'secret', 'state']);
      assert.equal(exchange.body.platformId, PLATFORM);
      assert.equal(exchange.body.secret, 'sh-secret');
      assert.equal(exchange.body.code, 'c1');
      // تُعاد كما وصلت لا كما نولّدها.
      assert.equal(exchange.body.state, 'STATE-FROM-CENTER');
    },
  );
});

test('الاستقبال الناجح يفتح جلسة عمرها عمر الرمز لا أطول', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'admin', is_active: 1, perms: null },
  });

  await withFetch(
    { '/api/token': async () => Response.json({ token: await token(), next: '/' }) },
    async () => {
      const res = await handleCallback(req('/auth/callback?code=c1&state=s'), env, config);
      assert.equal(res.status, 302);

      const put = kv.puts.find((p) => p.key.startsWith('sess:'));
      assert.ok(put, 'يجب أن تُفتح جلسة');
      // الرمز يعيش ٩٠٠ ثانية، فالجلسة لا تتجاوزها — وإلا بقي الموقوف
      // مركزياً داخلاً حتى ينتهي كوكيه لا حتى ينتهي رمزه.
      assert.ok(put.options.expirationTtl <= 900, `عمر الجلسة ${put.options.expirationTtl}`);
      assert.ok(put.options.expirationTtl > 800);
      assert.equal(JSON.parse(put.value).sub, 'u1');
    },
  );
});

test('الوجهة العائدة من المبادلة تُنقّى قبل التحويل إليها', async () => {
  const { env, config } = setup({ member: { id: 'u1', role: 'admin', is_active: 1, perms: null } });

  for (const hostile of ['//evil.sa', 'https://evil.sa/x', '/%2f%2fevil.sa', '/\\evil.sa']) {
    await withFetch(
      { '/api/token': async () => Response.json({ token: await token(), next: hostile }) },
      async () => {
        const res = await handleCallback(req('/auth/callback?code=c1&state=s'), env, config);
        assert.equal(res.headers.get('location'), '/', `${hostile} يجب أن يعود إلى الجذر`);
      },
    );
  }
});

test('وجهة سليمة من المبادلة تُتَّبع', async () => {
  const { env, config } = setup({ member: { id: 'u1', role: 'admin', is_active: 1, perms: null } });

  await withFetch(
    { '/api/token': async () => Response.json({ token: await token(), next: '/transactions' }) },
    async () => {
      const res = await handleCallback(req('/auth/callback?code=c1&state=s'), env, config);
      assert.equal(res.headers.get('location'), '/transactions');
    },
  );
});

test('رفض المركز للمبادلة يعطي رمزاً عاماً ولا يكشف تفصيلاً', async () => {
  const { env, config } = setup();

  await withFetch(
    { '/api/token': () => new Response(JSON.stringify({ error: 'invalid_code' }), { status: 400 }) },
    async () => {
      const res = await handleCallback(req('/auth/callback?code=c1&state=s'), env, config);
      assert.equal(res.headers.get('location'), '/denied?r=auth_failed');
    },
  );
});

test('بلا سرّ لا تقع المبادلة أصلاً', async () => {
  // `null` لا `undefined`: الأخيرة تُعيد تفعيل القيمة الافتراضية للمعامل.
  const { env, config } = setup({ secret: null });

  await withFetch({}, async (calls) => {
    const res = await handleCallback(req('/auth/callback?code=c1&state=s'), env, config);
    assert.equal(res.headers.get('location'), '/denied?r=auth_failed');
    assert.equal(calls.length, 0, 'لا طلب يحمل سرّاً مفقوداً');
  });
});

// ─────────────────────────── التبليغ العكسي ───────────────────────────

test('التبليغ يرسل البريد والحالة بأسماء المركز', async () => {
  const { env, config } = setup();

  await withFetch(
    { '/api/internal/access': () => Response.json({ ok: true }) },
    async (calls) => {
      await reportAccessChange(env, config, {
        email: ' F@Example.com ',
        state: 'revoked',
        reason: 'انتهى التعاقد',
      });

      const call = calls.find((c) => c.url.endsWith('/api/internal/access'));
      assert.deepEqual(Object.keys(call.body).sort(), [
        'email',
        'platformId',
        'reason',
        'secret',
        'state',
      ]);
      assert.equal(call.body.email, 'F@Example.com');
      assert.equal(call.body.state, 'revoked');
      assert.equal(call.body.platformId, PLATFORM);
    },
  );
});

test('التبليغ بلا سبب لا يرسل الحقل فارغاً', async () => {
  const { env, config } = setup();

  await withFetch(
    { '/api/internal/access': () => Response.json({ ok: true }) },
    async (calls) => {
      await reportAccessChange(env, config, { email: 'f@example.com', state: 'granted' });
      const call = calls.find((c) => c.url.endsWith('/api/internal/access'));
      assert.equal('reason' in call.body, false);
    },
  );
});

test('حالة غير مقبولة أو بريد مفقود يُردّان قبل حمل السرّ في طلب', async () => {
  const { env, config } = setup();

  await withFetch({}, async (calls) => {
    await assert.rejects(
      () => reportAccessChange(env, config, { email: 'f@example.com', state: 'disabled' }),
      (e) => e.code === 'bad_access_state',
    );
    await assert.rejects(
      () => reportAccessChange(env, config, { email: '  ', state: 'revoked' }),
      (e) => e.code === 'missing_email',
    );
    assert.equal(calls.length, 0);
  });
});

// ──────────────────────────── جدول الأعضاء ────────────────────────────

test('التحديث لا يمسّ الدور ولا حالة التفعيل', async () => {
  const { db, env, config } = setup({
    member: { id: 'u1', role: 'writer', is_active: 1, perms: null },
  });
  await upsertMember(env, config, { sub: 'u1', name: 'فهد', email: 'f@example.com' });

  const update = db.statements.find((s) => s.trimStart().startsWith('UPDATE'));
  assert.ok(update, 'صفٌّ قائم يُحدَّث');

  assert.match(update, /display_name = \?/);
  assert.match(update, /email = \?/);
  // لو حُدّث الدور لعاد كل مستخدم إلى الافتراضي عند كل دخول،
  // ولو حُدّثت حالة التفعيل لفُكّ إيقاف الموقوف بمجرّد محاولته الدخول.
  assert.doesNotMatch(update, /\brole\b/);
  assert.doesNotMatch(update, /\bis_active\b/);

  /* ولا `INSERT` على صفٍّ قائم.

     كان `INSERT … ON CONFLICT DO UPDATE`، وهو يسقط على جدولٍ فيه عمود
     `NOT NULL` بلا افتراضي لا تعرفه الحزمة: SQLite يفحص `NOT NULL` على
     الصفّ المقترَح قبل أن يكتشف التعارض الذي يحوّله إلى التحديث. وهو ما
     كان يُسقط كل دخول في `naf-marketing` — انظر `store.test.js`. */
  assert.equal(db.statements.some((s) => s.includes('INSERT INTO')), false);
});

test('مخطّط جدول قائم يُضبط من البيئة وحدها', async () => {
  const kv = fakeKV();
  const db = fakeDB(null);
  const env = {
    AUTH_ISSUER: ISSUER,
    PLATFORM_ID: PLATFORM,
    AUTH_KV: kv,
    DB: db,
    MEMBERS_TABLE: 'users',
    MEMBERS_ID_COLUMN: 'id',
    MEMBERS_NAME_COLUMN: 'name',
    MEMBERS_ROLE_COLUMN: 'role_name',
    MEMBERS_TIME_FORMAT: 'iso',
    DEFAULT_ROLE: 'writer',
  };
  const config = createConfig(env);
  await upsertMember(env, config, { sub: 'u9', name: 'فهد', email: 'f@example.com' });

  const insert = db.statements.find((s) => s.includes('INSERT INTO'));
  assert.match(insert, /INSERT INTO users \(id, name, email, role_name, is_active, created_at/);
  assert.match(insert, /ON CONFLICT\(id\)/);
  assert.equal(config.defaultRole, 'writer');
});

test('اسم جدول أو عمود غير سليم يوقف الاستعلام قبل بنائه', async () => {
  const { env, config } = setup();
  config.schema.table = 'users; DROP TABLE users';
  await assert.rejects(() => upsertMember(env, config, { sub: 'u1' }));
});

test('عمود اختياري يُعطَّل بالقيمة - فلا يدخل الاستعلام', async () => {
  const kv = fakeKV();
  const db = fakeDB(null);
  const env = {
    AUTH_ISSUER: ISSUER,
    PLATFORM_ID: PLATFORM,
    AUTH_KV: kv,
    DB: db,
    MEMBERS_TABLE: 'users',
    MEMBERS_ID_COLUMN: 'id',
    MEMBERS_ROLE_COLUMN: 'role_name',
    MEMBERS_PERMS_COLUMN: '-',
    MEMBERS_LAST_SEEN_COLUMN: '-',
  };
  const config = createConfig(env);
  assert.equal(config.schema.perms, null);
  assert.equal(config.schema.lastSeenAt, null);

  await upsertMember(env, config, { sub: 'u1', name: 'فهد', email: 'f@example.com' });
  const insert = db.statements.find((s) => s.includes('INSERT INTO'));
  assert.doesNotMatch(insert, /perms/);
  assert.doesNotMatch(insert, /last_seen_at/);

  // والقراءة أيضاً لا تطلب عموداً غير موجود.
  await getMember(env, config, 'u1');
  const select = db.statements.find((s) => s.includes('SELECT'));
  assert.doesNotMatch(select, /perms/);
});


// ───────────── شكل الردّ يتبع طبيعة الطلب لا بادئة مساره ─────────────

test('تنقّلٌ إلى مسار برمجي (رابط تنزيل) يُحوَّل ولا يأخذ JSON', async () => {
  const { env, config } = setup();
  const { response } = await authenticate(
    reqWith('/api/reports/download?key=r/a.pdf', { mode: 'navigate' }),
    env,
    config,
  );

  // البادئة `‎/api/` تقول «برمجي»، وطبيعة الطلب تقول «تنقّل» — والثانية أولى:
  // ردُّ JSON على رابطٍ يفتحه المستخدم يعرض عليه نصّاً خاماً.
  assert.equal(response.status, 302);
  assert.match(response.headers.get('location'), new RegExp(`^${ISSUER}/go/${PLATFORM}`));
});

test('نداء fetch إلى مسار خارج البادئات يأخذ ٤٠١ لا تحويلة', async () => {
  const { env, config } = setup();
  const { response } = await authenticate(reqWith('/posts', { mode: 'cors' }), env, config);

  assert.equal(response.status, 401);
  const body = await response.json();
  assert.match(body.login, new RegExp(`^${ISSUER}/go/${PLATFORM}`));
});

test('بلا Sec-Fetch-Mode يُحكم بـAccept', async () => {
  const { env, config } = setup();

  const doc = await authenticate(
    reqWith('/api/reports/download', { accept: 'text/html,application/xhtml+xml' }),
    env,
    config,
  );
  assert.equal(doc.response.status, 302);

  const api = await authenticate(reqWith('/posts', { accept: 'application/json' }), env, config);
  assert.equal(api.response.status, 401);
});

test('الرفض على نداء برمجي يردّ ٤٠٣ بجسم يُقرأ لا تحويلة داخلية', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'writer', is_active: 0, perms: null },
  });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: await token(), exp: 0 }));

  await withFetch({}, async () => {
    const { response } = await authenticate(
      reqWith('/api/members', { cookie: 'naf_sid=s1', mode: 'cors' }),
      env,
      config,
    );

    // التحويلة هنا داخلية فيتبعها fetch بنجاح ويستقبل صفحةً نصّاً، فيسقط
    // تحليل JSON بخطأ لا صلة له بالسبب — والعضو الموقوف يقرأ «خطأ تحليل».
    assert.equal(response.status, 403);
    const body = await response.json();
    assert.equal(body.reason, 'inactive');
    assert.equal(body.denied, '/denied?r=inactive');
  });
});

test('الرفض على تنقّل يبقى تحويلةً إلى صفحة المنع', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'writer', is_active: 0, perms: null },
  });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: await token(), exp: 0 }));

  await withFetch({}, async () => {
    const { response } = await authenticate(
      reqWith('/posts', { cookie: 'naf_sid=s1', mode: 'navigate' }),
      env,
      config,
    );
    assert.equal(response.headers.get('location'), '/denied?r=inactive');
  });
});

test('الوسيط يعيد محتوى الرمز بعد التحقق منه في الطلب نفسه', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'admin', is_active: 1, perms: null },
  });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1', token: await token(), exp: 0 }));

  await withFetch({}, async () => {
    const { claims } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);
    // البريد والاسم من محتوى تحقّقنا منه، لا من فكّ ترميز بلا تحقّق.
    assert.equal(claims.sub, 'u1');
    assert.equal(claims.aud, PLATFORM);
  });
});
