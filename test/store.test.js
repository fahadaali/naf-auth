// جدول الأعضاء على SQLite حقيقي — لا على بديل يقول «نعم» لكل جملة.
//
// العطل الذي يحرسه هذا الملف: `upsertMember` كان `INSERT … ON CONFLICT DO
// UPDATE`، وهو يسقط على **صفٍّ قائم** إن كان في الجدول عمودٌ `NOT NULL` بلا
// افتراضي لا تعرفه الحزمة — لأن SQLite يفحص `NOT NULL` على الصفّ المقترَح
// قبل أن يكتشف تعارض التفرّد الذي يحوّله إلى `DO UPDATE`.
//
// وهو ما كان يقع في `naf-marketing`: جدول `users` القائم فيه
// `password_hash TEXT NOT NULL` بلا افتراضي، فكان كل دخول يسقط بـ
// `NOT NULL constraint failed` ويصل صاحبَه «تعذّر التحقق من دخولك».
//
// ولذلك يُشغَّل الفحص على `node:sqlite` لا على بديل: بديلٌ يقبل كل شيء ما
// كان ليُظهر العطل أصلاً — وهو ما جعله يعيش حتى ظهر في متصفّح المالك.

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';

import { createConfig } from '../src/index.js';
import { getMember, upsertMember } from '../src/store.js';

/** غلاف يقدّم واجهة D1 (`prepare/bind/first/run`) فوق `node:sqlite`. */
function d1(db) {
  return {
    prepare(sql) {
      return {
        args: [],
        bind(...args) {
          this.args = args;
          return this;
        },
        first() {
          const row = db.prepare(sql).get(...this.args);
          return row ?? null;
        },
        run() {
          db.prepare(sql).run(...this.args);
          return { success: true };
        },
      };
    },
  };
}

function envFor(db, overrides = {}) {
  return {
    AUTH_ISSUER: 'https://id.naf.example',
    PLATFORM_ID: 'naf-test',
    AUTH_CLIENT_SECRET: 's',
    AUTH_KV: {},
    DB: d1(db),
    ...overrides,
  };
}

const CLAIMS = { sub: 'sub-1', name: 'فهد', email: 'f@naflaw.sa' };

// ─────────── المخطّط الافتراضي (§٥) ───────────

test('المخطّط الافتراضي: أول دخول يُنشئ، والثاني يحدّث ولا يمسّ الدور', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE members (
    user_id TEXT PRIMARY KEY, display_name TEXT, email TEXT,
    role TEXT NOT NULL DEFAULT 'viewer', perms TEXT,
    is_active INTEGER NOT NULL DEFAULT 1, last_seen_at INTEGER,
    created_at INTEGER NOT NULL)`);

  const env = envFor(db);
  const config = createConfig(env);

  const first = await upsertMember(env, config, CLAIMS);
  assert.equal(first.id, 'sub-1');
  assert.equal(first.role, 'viewer');
  assert.equal(first.isActive, true);

  // مسؤول المنصة يرقّيه
  db.exec(`UPDATE members SET role = 'admin' WHERE user_id = 'sub-1'`);

  const second = await upsertMember(env, config, { ...CLAIMS, name: 'فهد الجديد' });
  // الترقية باقية — ولو أُعيد كل مستخدم إلى الافتراضي لضاعت عند كل دخول.
  assert.equal(second.role, 'admin');
  assert.equal(db.prepare('SELECT display_name FROM members').get().display_name, 'فهد الجديد');
});

test('المخطّط الافتراضي: الموقوف يبقى موقوفاً بعد دخوله', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE members (
    user_id TEXT PRIMARY KEY, display_name TEXT, email TEXT,
    role TEXT NOT NULL DEFAULT 'viewer', perms TEXT,
    is_active INTEGER NOT NULL DEFAULT 1, last_seen_at INTEGER,
    created_at INTEGER NOT NULL)`);

  const env = envFor(db);
  const config = createConfig(env);

  await upsertMember(env, config, CLAIMS);
  db.exec(`UPDATE members SET is_active = 0 WHERE user_id = 'sub-1'`);

  const again = await upsertMember(env, config, CLAIMS);
  // ولو فُكّ الإيقاف بمجرّد المحاولة لما بقي إيقافٌ قائماً أصلاً.
  assert.equal(again.isActive, false);
});

// ─────────── جدول قائم فيه عمود إلزامي لا تعرفه الحزمة ───────────

/** جدول `users` في `naf-marketing` حرفياً — من `migrations/0001_init.sql`. */
function marketingSchema(db) {
  db.exec(`CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role_name     TEXT NOT NULL CHECK (role_name IN ('writer','marketing_manager','general_manager')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')))`);
}

function marketingConfig(db) {
  const env = envFor(db, {
    MEMBERS_TABLE: 'users',
    MEMBERS_ID_COLUMN: 'id',
    MEMBERS_NAME_COLUMN: 'name',
    MEMBERS_ROLE_COLUMN: 'role_name',
    MEMBERS_TIME_FORMAT: 'iso',
    MEMBERS_PERMS_COLUMN: '-',
    MEMBERS_LAST_SEEN_COLUMN: '-',
    DEFAULT_ROLE: 'writer',
  });
  return { env, config: createConfig(env) };
}

test('صفٌّ أنشأه onClaims يُحدَّث ولا يسقط على عمود NOT NULL لا تعرفه الحزمة', async () => {
  const db = new DatabaseSync(':memory:');
  marketingSchema(db);
  const { env, config } = marketingConfig(db);

  // ما يفعله `onClaims` في المنصة: ينشئ الصفّ ومعه أعمدتها الإلزامية.
  db.prepare(
    `INSERT INTO users (id, name, email, password_hash, role_name, is_active)
     VALUES (?, ?, ?, '', 'writer', 1)`,
  ).run('sub-1', 'فهد', 'f@naflaw.sa');

  // وهنا كان يسقط: `INSERT … ON CONFLICT` يفحص NOT NULL قبل التعارض.
  const member = await upsertMember(env, config, { ...CLAIMS, name: 'فهد الجديد' });

  assert.equal(member.id, 'sub-1');
  assert.equal(member.role, 'writer');
  assert.equal(member.isActive, true);
  // والاسم حُدِّث، والعمود الذي لا تعرفه الحزمة لم يُمسّ.
  const row = db.prepare('SELECT name, password_hash FROM users WHERE id = ?').get('sub-1');
  assert.equal(row.name, 'فهد الجديد');
  assert.equal(row.password_hash, '');
});

test('ترقية العضو باقية على الجدول القائم بعد دخوله ثانيةً', async () => {
  const db = new DatabaseSync(':memory:');
  marketingSchema(db);
  const { env, config } = marketingConfig(db);

  db.prepare(
    `INSERT INTO users (id, name, email, password_hash, role_name, is_active)
     VALUES (?, ?, ?, '', 'general_manager', 1)`,
  ).run('sub-1', 'فهد', 'f@naflaw.sa');

  const member = await upsertMember(env, config, CLAIMS);
  assert.equal(member.role, 'general_manager');
});

test('دخولٌ ثانٍ متزامن لا يُسقط الاستقبال — التعارض سباقٌ لا خطأ', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE members (
    user_id TEXT PRIMARY KEY, display_name TEXT, email TEXT,
    role TEXT NOT NULL DEFAULT 'viewer', perms TEXT,
    is_active INTEGER NOT NULL DEFAULT 1, last_seen_at INTEGER,
    created_at INTEGER NOT NULL)`);

  const env = envFor(db);
  const config = createConfig(env);

  // صفٌّ كُتب بيننا وبين قراءتنا — كما يقع حين يبلغ دخولان معاً.
  db.prepare(
    `INSERT INTO members (user_id, display_name, email, role, is_active, created_at)
     VALUES (?, ?, ?, 'admin', 1, 0)`,
  ).run('sub-2', 'سارة', 's@naflaw.sa');

  const member = await upsertMember(env, config, { sub: 'sub-2', name: 'سارة', email: 's@naflaw.sa' });
  assert.equal(member.role, 'admin');
});

test('مطالبةٌ بلا اسم لا تمحو الاسم القائم ولا تُسقط الدخول', async () => {
  const db = new DatabaseSync(':memory:');
  marketingSchema(db);
  const { env, config } = marketingConfig(db);

  db.prepare(
    `INSERT INTO users (id, name, email, password_hash, role_name, is_active)
     VALUES (?, ?, ?, '', 'writer', 1)`,
  ).run('sub-1', 'فهد', 'f@naflaw.sa');

  // رمزٌ بلا `name`: لو كُتب NULL لسقط على `name TEXT NOT NULL`.
  const member = await upsertMember(env, config, { sub: 'sub-1', email: 'f@naflaw.sa' });

  assert.equal(member.role, 'writer');
  assert.equal(db.prepare('SELECT name FROM users WHERE id = ?').get('sub-1').name, 'فهد');
});

test('getMember يعيد null لمن لا صفّ له', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE members (
    user_id TEXT PRIMARY KEY, display_name TEXT, email TEXT,
    role TEXT NOT NULL DEFAULT 'viewer', perms TEXT,
    is_active INTEGER NOT NULL DEFAULT 1, last_seen_at INTEGER,
    created_at INTEGER NOT NULL)`);
  const env = envFor(db);
  assert.equal(await getMember(env, createConfig(env), 'لا أحد'), null);
});
