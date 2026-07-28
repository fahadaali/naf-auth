// naf-auth — جدول الأعضاء المحلي
//
// ملاحظة على البنية: §٤ من الوثيقة تعدّ خمسة ملفات في `src/`، وهذا سادسها.
// السبب أن الوسيط يقرأ العضو ومسار الاستقبال يكتبه، فلو بقي الاستعلام في
// أحدهما لاستورده الآخر — ومنطق قاعدة واحد في موضعين أسوأ من ملف زائد.
//
// وأسماء الجدول والأعمدة قابلة للضبط لأن منصة قائمة قد يكون لها جدول أعضاء
// سابق باسم آخر وأعمدة بأسماء أخرى. القيم الافتراضية هي مخطّط §٥ حرفياً،
// فمنصة جديدة لا تضبط شيئاً، والمختلف يبقى في `wrangler.toml` وحده (§١٢).

import { assertIdentifier } from './safe.js';

/** مخطّط §٥ — الافتراضي لمنصة جديدة. */
export const DEFAULT_SCHEMA = {
  table: 'members',
  id: 'user_id',
  name: 'display_name',
  email: 'email',
  role: 'role',
  perms: 'perms',
  isActive: 'is_active',
  lastSeenAt: 'last_seen_at',
  createdAt: 'created_at',
};

/**
 * صيغة الوقت في أعمدة الوقت:
 *   `epoch` عدد ثوانٍ — مخطّط §٥
 *   `iso`   نصّ ISO 8601 — منصة قائمة تخزّن أوقاتها نصاً
 */
function stamp(timeFormat) {
  const now = new Date();
  return timeFormat === 'iso'
    ? now.toISOString().replace(/\.\d{3}Z$/, 'Z')
    : Math.floor(now.getTime() / 1000);
}

function columns(config) {
  const s = config.schema;
  assertIdentifier(s.table, 'اسم جدول الأعضاء');
  for (const field of ['id', 'name', 'email', 'role', 'isActive', 'createdAt']) {
    assertIdentifier(s[field], `عمود ${field}`);
  }
  // عمودان اختياريان: منصة قائمة قد لا يكون فيها أيّ منهما.
  if (s.perms) assertIdentifier(s.perms, 'عمود perms');
  if (s.lastSeenAt) assertIdentifier(s.lastSeenAt, 'عمود lastSeenAt');
  return s;
}

function parsePerms(raw) {
  if (raw == null || raw === '') return null;
  try {
    return JSON.parse(raw);
  } catch {
    // صلاحيات دقيقة تالفة لا تُسقط الطلب — تُعامل كغير موجودة ويبقى الدور.
    return null;
  }
}

/** قراءة العضو بمعرّفه المركزي (`sub`). */
export async function getMember(env, config, userId) {
  const c = columns(config);
  const permsSelect = c.perms ? `, ${c.perms} AS perms` : '';

  const row = await env[config.dbBinding]
    .prepare(
      `SELECT ${c.id} AS id, ${c.role} AS role, ${c.isActive} AS is_active${permsSelect}
       FROM ${c.table} WHERE ${c.id} = ?`,
    )
    .bind(userId)
    .first();

  if (!row) return null;
  return {
    id: row.id,
    role: row.role,
    perms: parsePerms(row.perms),
    isActive: Number(row.is_active) === 1,
  };
}

/**
 * إدراج العضو أو تحديثه (الخطوة ٥ في §٦-٢).
 *
 * أول دخول ينشئ السجلّ بالدور الافتراضي، ثم يرقّيه مسؤول المنصة من إعداداتها.
 * والدخول الثاني يحدّث الاسم والبريد وآخر ظهور — ولا يمسّ:
 *   - الدور: وإلا أُعيد كل مستخدم إلى الافتراضي عند كل دخول وضاعت الترقية
 *   - is_active: وإلا فُكّ إيقاف الموقوف بمجرّد محاولته الدخول
 *
 * ═══ يُقرأ أولاً ثم يُكتب — ولا `INSERT … ON CONFLICT` على صفٍّ قائم ═══
 *
 * كان واحداً: `INSERT` بكل الأعمدة و`ON CONFLICT(id) DO UPDATE`. وهو يسقط
 * على **صفٍّ قائم** إن كان في الجدول عمودٌ `NOT NULL` بلا قيمة افتراضية
 * لا تعرفه هذه الحزمة — لأن SQLite يفحص `NOT NULL` على الصفّ المقترَح
 * **قبل** أن يكتشف تعارض التفرّد الذي يحوّله إلى `DO UPDATE`. فالجملة تُردّ
 * ولا تصل إلى فرع التحديث أصلاً.
 *
 * وهذا ليس فرضاً نظرياً: `naf-marketing` تربط الحزمة بجدول `users` القائم،
 * وفيه `password_hash TEXT NOT NULL` بلا افتراضي — عمودٌ لا تعرفه الحزمة
 * ولا يجوز أن تعرفه. فكان كل دخول فيها يسقط بـ
 * `NOT NULL constraint failed: users.password_hash`، ويصل صاحبَه «تعذّر
 * التحقق من دخولك» بلا سبب ظاهر.
 *
 * فصار: إن وُجد الصفّ حُدِّثت أعمدتُه المملوكة وحدها ولا تُمسّ الأعمدة
 * الأخرى؛ وإن لم يوجد أُدرج. والإدراج وحده يبقى مشروطاً بأن يحتمله الجدول —
 * ومنصةٌ لجدولها أعمدة إلزامية تخصّها تُنشئ صفّها في `onClaims`، وهو موضعه
 * المكتوب. عندئذ يجد `upsertMember` الصفّ ويحدّثه.
 */
export async function upsertMember(env, config, claims) {
  const c = columns(config);
  const now = stamp(config.timeFormat);
  const db = env[config.dbBinding];

  const existing = await getMember(env, config, claims.sub);

  if (existing) {
    /* الأعمدة المملوكة وحدها: الاسم والبريد وآخر ظهور. ولا الدور ولا حالة
       التفعيل — وإلا أُعيد كل مستخدم إلى الافتراضي وفُكّ إيقاف الموقوف. */
    const sets = [`${c.name} = ?`, `${c.email} = ?`];
    const values = [claims.name ?? null, claims.email ?? null];

    if (c.lastSeenAt) {
      sets.push(`${c.lastSeenAt} = ?`);
      values.push(now);
    }
    values.push(claims.sub);

    await db
      .prepare(`UPDATE ${c.table} SET ${sets.join(', ')} WHERE ${c.id} = ?`)
      .bind(...values)
      .run();

    return getMember(env, config, claims.sub);
  }

  const cols = [c.id, c.name, c.email, c.role, c.isActive, c.createdAt];
  const values = [claims.sub, claims.name ?? null, claims.email ?? null, config.defaultRole, 1, now];

  if (c.lastSeenAt) {
    cols.push(c.lastSeenAt);
    values.push(now);
  }

  const placeholders = cols.map(() => '?').join(', ');

  /* `DO NOTHING` لا `DO UPDATE`: دخولان متزامنان لعضوٍ جديد يبلغان هنا معاً،
     فيُدرج أحدهما ويجد الآخر تعارضاً — وهو سباقٌ لا خطأ. والقراءة بعده
     تعطي الصفّ الذي كُتب أياً كان كاتبه. */
  await db
    .prepare(
      `INSERT INTO ${c.table} (${cols.join(', ')}) VALUES (${placeholders})
       ON CONFLICT(${c.id}) DO NOTHING`,
    )
    .bind(...values)
    .run();

  return getMember(env, config, claims.sub);
}

/** تحديث آخر ظهور وحده — يُستدعى من الوسيط عند الطلبات اللاحقة إن رُغب. */
export async function touchMember(env, config, userId) {
  const c = columns(config);
  if (!c.lastSeenAt) return;
  await env[config.dbBinding]
    .prepare(`UPDATE ${c.table} SET ${c.lastSeenAt} = ? WHERE ${c.id} = ?`)
    .bind(stamp(config.timeFormat), userId)
    .run();
}
