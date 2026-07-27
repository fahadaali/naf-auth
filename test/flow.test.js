// اختبارات التدفّق: الوسيط ومسار الاستقبال وجدول الأعضاء،
// على بدائل بسيطة لـ KV و D1 — بلا شبكة وبلا حزمة اختبار خارجية.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createConfig } from '../src/index.js';
import { authenticate, isPublicPath } from '../src/middleware.js';
import { handleCallback } from '../src/callback.js';
import { getMember, upsertMember } from '../src/store.js';

function fakeKV() {
  const store = new Map();
  return {
    store,
    async get(key, type) {
      const value = store.get(key);
      if (value === undefined) return null;
      return type === 'json' ? JSON.parse(value) : value;
    },
    async put(key, value) {
      store.set(key, value);
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

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

function setup({ member = null } = {}) {
  const kv = fakeKV();
  const db = fakeDB(member);
  const env = {
    AUTH_ISSUER: 'https://id.naf.example',
    PLATFORM_ID: 'naf-test',
    AUTH_KV: kv,
    DB: db,
  };
  return { kv, db, env, config: createConfig(env) };
}

const req = (path, cookie) =>
  new Request(`https://platform.example${path}`, cookie ? { headers: { cookie } } : undefined);

test('المسارات العامة مكتوبة صراحةً وما عداها محمي', () => {
  const { config } = setup();
  for (const path of ['/auth/callback', '/denied', '/health', '/assets/app.js']) {
    assert.equal(isPublicPath(path, config), true, `${path} يجب أن يكون عاماً`);
  }
  // أي مسار جديد محمي افتراضياً (§٦-١) — بما فيه ما يشبه العام.
  for (const path of ['/', '/posts', '/admin', '/health-check', '/assets', '/denied-x']) {
    assert.equal(isPublicPath(path, config), false, `${path} يجب أن يكون محمياً`);
  }
});

test('بلا كوكي: تحويل إلى المركز مع حالة مخزَّنة ووجهة منقّاة', async () => {
  const { kv, env, config } = setup();
  const { response } = await authenticate(req('/posts?page=2'), env, config);

  assert.equal(response.status, 302);
  const location = new URL(response.headers.get('location'));
  assert.equal(location.origin + location.pathname, 'https://id.naf.example/go/naf-test');
  assert.equal(location.searchParams.get('next'), '/posts?page=2');

  const state = location.searchParams.get('state');
  assert.match(state, /^[0-9a-f]{64}$/);
  assert.deepEqual(await kv.get(`st:${state}`, 'json'), { next: '/posts?page=2' });
});

test('وجهة خارجية لا تصل إلى المركز أصلاً', async () => {
  const { env, config } = setup();
  // المسار يأتي من عنوان الطلب، فالوجهة المخزَّنة تمرّ على التنقية دائماً.
  const { response } = await authenticate(req('/%2F%2Fevil.sa'), env, config);
  const next = new URL(response.headers.get('location')).searchParams.get('next');
  assert.equal(next.startsWith('/'), true);
  assert.equal(next.startsWith('//'), false);
});

test('جلسة منتهية تعود إلى المركز ولا تجدّد نفسها', async () => {
  const { env, config } = setup();
  const { response, user } = await authenticate(req('/posts', 'naf_sid=ghost'), env, config);
  assert.equal(user, undefined);
  assert.equal(response.status, 302);
  assert.match(response.headers.get('location'), /^https:\/\/id\.naf\.example\/go\//);
});

test('عضو موقوف محلياً يُرفض رغم جلسته', async () => {
  const { kv, env, config } = setup({ member: { id: 'u1', role: 'writer', is_active: 0, perms: null } });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1' }));

  const { response, user } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);
  assert.equal(user, undefined);
  assert.equal(response.headers.get('location'), '/denied?r=inactive');
});

test('عضو نشط يُحقن في السياق بدوره وصلاحياته', async () => {
  const { kv, env, config } = setup({
    member: { id: 'u1', role: 'general_manager', is_active: 1, perms: '{"x":true}' },
  });
  await kv.put('sess:s1', JSON.stringify({ sub: 'u1' }));

  const { user, response } = await authenticate(req('/posts', 'naf_sid=s1'), env, config);
  assert.equal(response, undefined);
  assert.deepEqual(user, { id: 'u1', role: 'general_manager', perms: { x: true } });
});

test('الاستقبال بلا حالة أو بحالة غير مخزَّنة يُرفض', async () => {
  const { env, config } = setup();

  const noState = await handleCallback(req('/auth/callback?code=c1'), env, config);
  assert.equal(noState.headers.get('location'), '/denied?r=bad_state');

  const unknown = await handleCallback(req('/auth/callback?code=c1&state=deadbeef'), env, config);
  assert.equal(unknown.headers.get('location'), '/denied?r=bad_state');
});

test('الاستقبال بلا رمز يعيد التحويل إلى المركز', async () => {
  const { env, config } = setup();
  const res = await handleCallback(req('/auth/callback'), env, config);
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location'), /^https:\/\/id\.naf\.example\/go\//);
});

test('الحالة تُستهلك مرة واحدة', async () => {
  const { kv, env, config } = setup();
  await kv.put('st:abc', JSON.stringify({ next: '/posts' }));

  // المبادلة ستفشل (لا سرّ ولا شبكة) لكن الحالة تُحذف قبل ذلك.
  await handleCallback(req('/auth/callback?code=c1&state=abc'), env, config);
  assert.equal(kv.store.has('st:abc'), false);

  const replay = await handleCallback(req('/auth/callback?code=c1&state=abc'), env, config);
  assert.equal(replay.headers.get('location'), '/denied?r=bad_state');
});

test('فشل المبادلة يعطي رمزاً عاماً ولا يكشف تفصيلاً', async () => {
  const { kv, env, config } = setup();
  await kv.put('st:abc', JSON.stringify({ next: '/posts' }));
  // لا سرّ في البيئة، فالمبادلة تفشل قبل أي اتصال.
  const res = await handleCallback(req('/auth/callback?code=c1&state=abc'), env, config);
  assert.equal(res.headers.get('location'), '/denied?r=auth_failed');
});

test('التحديث لا يمسّ الدور ولا حالة التفعيل', async () => {
  const { db, env, config } = setup({ member: { id: 'u1', role: 'writer', is_active: 1, perms: null } });
  await upsertMember(env, config, { sub: 'u1', name: 'فهد', email: 'f@example.com' });

  const insert = db.statements.find((s) => s.includes('INSERT INTO'));
  const update = insert.slice(insert.indexOf('DO UPDATE SET'));

  assert.match(update, /display_name = excluded\.display_name/);
  assert.match(update, /email = excluded\.email/);
  // لو حُدّث الدور لعاد كل مستخدم إلى الافتراضي عند كل دخول،
  // ولو حُدّثت حالة التفعيل لفُكّ إيقاف الموقوف بمجرّد محاولته الدخول.
  assert.doesNotMatch(update, /\brole\b/);
  assert.doesNotMatch(update, /\bis_active\b/);
});

test('مخطّط جدول قائم يُضبط من البيئة وحدها', async () => {
  const kv = fakeKV();
  const db = fakeDB(null);
  const env = {
    AUTH_ISSUER: 'https://id.naf.example',
    PLATFORM_ID: 'naf-test',
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
    AUTH_ISSUER: 'https://id.naf.example',
    PLATFORM_ID: 'naf-test',
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
