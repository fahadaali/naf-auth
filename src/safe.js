// naf-auth — أدوات التنقية والتوليد
// بلا تبعيات خارجية. كل ما هنا دوال نقية أو تعتمد WebCrypto وحده.

/** محارف تحكّم قد يحذفها المتصفح من ترويسة Location فيتغيّر المسار بعد التنقية. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

/** معرّف SQL مقبول — يُستعمل قبل أي إقحام لاسم جدول أو عمود في استعلام. */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * تنقية `next` — أخطر نقطة في المسار كله (الاحتراز الأول في §١٠).
 *
 * يُقبل المسار فقط إذا:
 *   - بدأ بشرطة مائلة واحدة
 *   - ولم يبدأ بشرطتين  → `//evil.sa` عنوان بروتوكول-نسبي، أي موقع خارجي
 *   - ولم يحوِ نقطتين رأسيتين → `javascript:` و `https://evil.sa`
 * وإلا فالجذر.
 *
 * وزيادتان على نصّ الوثيقة، كلتاهما أضيق لا أوسع:
 *   - رفض الشرطة العكسية: المتصفحات تطويها إلى شرطة مائلة، فـ `/\evil.sa`
 *     يصل إلى `//evil.sa` ويتجاوز شرط «لم يبدأ بشرطتين» حرفياً.
 *   - رفض محارف التحكّم: تُحذف من الترويسة، فيصير `/\tevil` مساراً آخر.
 *
 * ملاحظة مقصودة: منع النقطتين الرأسيتين يشمل سلسلة الاستعلام، فمسار مثل
 * `/posts?q=a:b` يعود إلى الجذر. هذا نصّ الوثيقة، والأمان فيه مقدَّم على الراحة.
 *
 * ولا يكفي فحص النصّ كما وصل. القيمة تمرّ بالمركز ثم تعود إلينا، وقد نفكّ
 * ترميزها مرة أخرى قبل استعمالها — فـ`/%2f%2fevil.sa` يمرّ فحصاً ساذجاً ثم
 * يصير `//evil.sa` عندنا، وهي الثغرة نفسها بخطوة إضافية. لذلك يُفكّ الترميز
 * حتى يستقرّ، ويُفحص الشكلان: كما وصل، وكما سيؤول.
 *
 * وأن المركز فحصه لا يُغني: هذا الطرف يقرّر لنفسه.
 */
function looksSafe(value) {
  if (value[0] !== '/') return false;
  if (value[1] === '/') return false;
  if (value.includes(':')) return false;
  if (value.includes('\\')) return false;
  if (CONTROL_CHARS.test(value)) return false;
  return true;
}

/** يفكّ الترميز حتى يستقرّ. وتداخل أعمق من أربع طبقات لا سبب مشروع له. */
function decodeFully(value) {
  let current = value;
  for (let round = 0; round < 4; round += 1) {
    let decoded;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      return null;
    }
    if (decoded === current) return current;
    current = decoded;
  }
  return null;
}

export function safeNext(next) {
  if (typeof next !== 'string' || next.length === 0) return '/';
  if (!looksSafe(next)) return '/';

  const settled = decodeFully(next);
  if (settled === null || !looksSafe(settled)) return '/';

  return next;
}

/** رمز عشوائي بالنظام السداسي عشري — ٣٢ بايت من مولّد آمن. */
export function randomToken(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * معرّف الجلسة (الاحتراز السابع في §١٠): عشوائي بالكامل،
 * لا يُشتقّ من `sub` ولا من أي قيمة متوقَّعة.
 */
export function newSessionId() {
  return randomToken(32);
}

/*
 * لا مولّد حالة عابرة هنا: `state` يولّده المركز ويخزّنه مع رمز العبور،
 * ويطابق الاثنين عند المبادلة. وهذا الطرف يعيده كما وصله.
 */

/**
 * كوكي الجلسة (الاحتراز السادس في §١٠):
 * HttpOnly و Secure و SameSite=Lax و Path=/ — وبلا Domain مشترك بين المنصات،
 * لأن نطاقاً مشتركاً يجعل كوكي منصة صالحاً في أختها.
 */
export function sessionCookie(name, value, maxAgeSeconds) {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

export function clearCookie(name) {
  return `${name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

/**
 * قراءة كوكي بالتقسيم لا بتعبير نمطي — اسم الكوكي لا يُقحَم في نمط.
 *
 * وكوكيٌّ بالاسم نفسه قد يتكرّر: المتصفّح يرسل نسخةً لكل `Domain` و`Path`
 * كتبتها، ولا يقول أيُّها من أين. فواحدٌ تالفٌ لا يُنهي البحث — يُتخطّى
 * ويُكمَل إلى التالي. والوقوفُ عنده يُخرج صاحبَ جلسةٍ صحيحة لأن نسخةً
 * قديمة بالاسم نفسه تعذّر فكّ ترميزها، وهي حالٌ لا يملك صاحبها إصلاحها
 * إلا بمسح كوكيّات الموقع يدوياً.
 */
export function readCookie(request, name) {
  const header = request.headers.get('cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      /* نسخةٌ تالفة بالاسم نفسه: تُتخطّى، والبحث يمضي. */
    }
  }
  return null;
}

/** مقارنة بزمن ثابت — لمطابقة الحالة العابرة دون تسريب فرق التوقيت. */
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * حارس أسماء الجداول والأعمدة.
 * أسماء المخطّط تأتي من `wrangler.toml` لا من طلب المستخدم، لكنها تُقحَم
 * في نصّ الاستعلام حيث لا تنفع المعاملات — فتُفحَص قبل الإقحام لا بعده.
 */
export function assertIdentifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new Error(`naf-auth: اسم غير صالح لـ ${label}: ${String(value)}`);
  }
  return value;
}

/**
 * توحيد صورة المُصدِر بحذف الشرطة المائلة الأخيرة.
 *
 * `iss` يُطابَق حرفياً، و`https://id.example/` و `https://id.example` صورتان
 * لنطاق واحد. فلو كُتب في `wrangler.toml` بصورة وأصدر المركز بالأخرى
 * لرُفض كل رمز بـ `bad_issuer` — والسبب محارف لا منطق. تُوحَّد الصورتان هنا.
 */
export function normaliseIssuer(issuer) {
  return typeof issuer === 'string' ? issuer.replace(/\/+$/, '') : issuer;
}

/**
 * كوكي ربط الدخول بالمتصفّح.
 *
 * عمرُه خمس دقائق: رحلةُ الدخول ثوانٍ، وطولُه بلا فائدة يوسّع نافذة
 * الالتقاط. و`SameSite=Lax` كي يصل مع العودة من المركز — وهي تنقّلٌ علويّ
 * بطريقة `GET`، فـ`Strict` كان يمنعه فيسقط كل دخول.
 */
export function bindCookie(name, value, maxAgeSeconds = 300) {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

/**
 * أسماء مفاتيح الجلسة في KV — تجزئةُ المعرّف لا المعرّف.
 *
 * كان الاسم `sess:{sid}` و`sid` هو قيمة الكوكي حرفياً، والقيمة تحمل الرمز
 * الموقّع. فمن قرأ مساحة KV — رمزُ API بصلاحية قراءة، أو نسخةٌ احتياطية —
 * كان `list` يعطيه كوكيّات جلسات كل عضو بلا اشتقاق ولا تخمين: يُلصق الاسم
 * في متصفّح فيصير صاحبَه.
 *
 * فصار الاسم تجزئةً لا يُشتقّ منها الكوكي. والمعرّف ٣٢ بايتاً عشوائية،
 * فلا يُخمَّن ولا تنفع فيه جداول محسوبة — ولا حاجة إلى ملح.
 *
 * وأثرُ النشر: الجلسات القائمة تصير غير مقروءة مرّةً واحدة، فيعود أصحابها
 * إلى المركز ويدخلون بلا كلمة مرور — جلسةُ المركز قائمة. وعمرُها خمس عشرة
 * دقيقة على أبعد تقدير أصلاً.
 */
export async function sessionKeyFor(sid) {
  return `sess:${await sha256Hex(sid)}`;
}

export async function userIndexKeyFor(sub, sid) {
  return `usr:${sub}:${await sha256Hex(sid)}`;
}

/** تجزئة SHA-256 بالنظام السداسي عشري — لِما يُرسل بدل السرّ نفسه. */
export async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** فكّ ترميز base64url إلى بايتات. */
export function base64UrlToBytes(input) {
  const normalised = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** فكّ ترميز base64url إلى نصّ UTF-8. */
export function base64UrlToText(input) {
  return new TextDecoder().decode(base64UrlToBytes(input));
}

/** خطأ مصادقة برمز ثابت — الرمز للسجلّ، ولا يُعرض للمستخدم كما هو. */
export class AuthError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'AuthError';
    this.code = code;
  }
}
