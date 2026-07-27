// naf-auth — نقطة الدخول
// حزمة الجسر بين منصات ناف وخدمة الهوية المركزية `naf-id`.

import { DEFAULT_SCHEMA } from './store.js';
import { normaliseIssuer } from './safe.js';

export { authenticate, honoMiddleware, isPublicPath, pagesMiddleware, startLogin, deniedResponse } from './middleware.js';
export { handleCallback, pagesCallback, reportAccessChange } from './callback.js';
export { verifyToken, CLOCK_SKEW_SECONDS, JWKS_TTL_SECONDS } from './verify.js';
export { getMember, touchMember, upsertMember, DEFAULT_SCHEMA } from './store.js';
export {
  AuthError,
  clearCookie,
  newSessionId,
  newState,
  normaliseIssuer,
  randomToken,
  readCookie,
  safeNext,
  sessionCookie,
  timingSafeEqual,
} from './safe.js';

/** جلسة المنصة: ١٢ ساعة (§٥). */
const SESSION_TTL_SECONDS = 12 * 60 * 60;

/** الحالة العابرة قبل التحويل: ٥ دقائق (§٥). */
const STATE_TTL_SECONDS = 5 * 60;

/**
 * المسارات العامة المكتوبة صراحةً (§٦-١): مسار الاستقبال، وصفحة الرفض،
 * وفحص الصحة. وأي مسار جديد خارج هذه القائمة محمي افتراضياً.
 */
const DEFAULT_PUBLIC_PATHS = ['/auth/callback', '/denied', '/health'];

/** الأصول الساكنة — بادئات مُعلنة لا اجتهاد على الامتداد. */
const DEFAULT_PUBLIC_PREFIXES = ['/assets/'];

/**
 * رموز أسباب الرفض.
 *
 * رموز لا جُملاً: النصّ المعروض للمستخدم يأتي من `naf-terms.md` في سجلّ
 * التصميم، وصفحة `/denied` هي التي تترجم الرمز إلى المصطلح المسجَّل.
 * ولو حملت الحزمة الجملة لصارت مصدر نصّ ثانياً خارج السجلّ.
 *
 * أمّا السبب النصّي القادم من المركز فيُمرَّر كما هو (الاحتراز الثامن في §١٠).
 */
const DEFAULT_REASONS = {
  inactive: 'inactive',
  notMember: 'not_member',
  badState: 'bad_state',
  authFailed: 'auth_failed',
};

/** `-` تعني: هذا العمود غير موجود في جدول هذه المنصة. */
function optionalColumn(value) {
  const trimmed = String(value).trim();
  return trimmed === '-' || trimmed === '' ? null : trimmed;
}

function required(value, name) {
  if (!value || typeof value !== 'string') {
    throw new Error(`naf-auth: ${name} مطلوب ولا يُخمَّن`);
  }
  return value;
}

/**
 * بناء الإعداد.
 *
 * القيم التي تختلف بين منصة وأخرى تُقرأ من `env` أي من `wrangler.toml` (§١٢).
 * ولا شيء منها مكتوب في الحزمة: لا معرّف منصة ولا نطاق ولا سرّ.
 */
export function createConfig(env, overrides = {}) {
  const schema = { ...DEFAULT_SCHEMA, ...(overrides.schema || {}) };

  // مخطّط جدول قائم يُضبط من `wrangler.toml` دون تعديل كود المنصة.
  // والعمودان الاختياريان يُعطَّلان بالقيمة `-`: جدول أعضاء قائم قد لا يحوي
  // عمود صلاحيات دقيقة ولا عمود آخر ظهور، والقيمة الفارغة في TOML لا تكفي
  // لإلغاء الافتراضي لأنها تُقرأ كغياب لا كنفي.
  if (env.MEMBERS_TABLE) schema.table = env.MEMBERS_TABLE;
  if (env.MEMBERS_ID_COLUMN) schema.id = env.MEMBERS_ID_COLUMN;
  if (env.MEMBERS_NAME_COLUMN) schema.name = env.MEMBERS_NAME_COLUMN;
  if (env.MEMBERS_EMAIL_COLUMN) schema.email = env.MEMBERS_EMAIL_COLUMN;
  if (env.MEMBERS_ROLE_COLUMN) schema.role = env.MEMBERS_ROLE_COLUMN;
  if (env.MEMBERS_ACTIVE_COLUMN) schema.isActive = env.MEMBERS_ACTIVE_COLUMN;
  if (env.MEMBERS_CREATED_COLUMN) schema.createdAt = env.MEMBERS_CREATED_COLUMN;
  if (env.MEMBERS_PERMS_COLUMN) schema.perms = optionalColumn(env.MEMBERS_PERMS_COLUMN);
  if (env.MEMBERS_LAST_SEEN_COLUMN) schema.lastSeenAt = optionalColumn(env.MEMBERS_LAST_SEEN_COLUMN);

  const kvBinding = overrides.kvBinding || env.AUTH_KV_BINDING || 'AUTH_KV';

  return {
    issuer: normaliseIssuer(required(overrides.issuer || env.AUTH_ISSUER, 'AUTH_ISSUER')),
    platformId: required(overrides.platformId || env.PLATFORM_ID, 'PLATFORM_ID'),

    // الأسماء وحدها هنا، لا القيم: السرّ يُقرأ من `env` عند الحاجة إليه.
    secretBinding: overrides.secretBinding || 'AUTH_CLIENT_SECRET',
    dbBinding: overrides.dbBinding || env.AUTH_DB_BINDING || 'DB',
    kvBinding,
    kv: overrides.kv || ((e) => {
      const ns = e[kvBinding];
      if (!ns) throw new Error(`naf-auth: مساحة KV غير مربوطة (${kvBinding})`);
      return ns;
    }),

    schema,
    // الدور الافتراضي لأول دخول. مخطّط §٥ يجعله `viewer`، ومنصة لها
    // أدوارها الخاصة تضبطه من `wrangler.toml` — فالصلاحيات موزّعة (§١).
    defaultRole: overrides.defaultRole || env.DEFAULT_ROLE || 'viewer',
    timeFormat: overrides.timeFormat || env.MEMBERS_TIME_FORMAT || 'epoch',

    cookieName: overrides.cookieName || env.AUTH_COOKIE_NAME || 'naf_sid',
    sessionTtlSeconds: overrides.sessionTtlSeconds || SESSION_TTL_SECONDS,
    stateTtlSeconds: overrides.stateTtlSeconds || STATE_TTL_SECONDS,

    deniedPath: overrides.deniedPath || '/denied',
    publicPaths: overrides.publicPaths || DEFAULT_PUBLIC_PATHS,
    publicPrefixes: overrides.publicPrefixes || DEFAULT_PUBLIC_PREFIXES,
    reasons: { ...DEFAULT_REASONS, ...(overrides.reasons || {}) },

    onError: overrides.onError || null,
    // يُستدعى بعد التحقق وقبل الإدراج — لمطابقة عضو قائم أو ترحيله.
    onClaims: overrides.onClaims || null,
  };
}

export {
  DEFAULT_PUBLIC_PATHS,
  DEFAULT_PUBLIC_PREFIXES,
  DEFAULT_REASONS,
  SESSION_TTL_SECONDS,
  STATE_TTL_SECONDS,
};
