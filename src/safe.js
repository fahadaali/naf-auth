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
 */
export function safeNext(next) {
  if (typeof next !== 'string' || next.length === 0) return '/';
  if (next[0] !== '/') return '/';
  if (next[1] === '/') return '/';
  if (next.includes(':')) return '/';
  if (next.includes('\\')) return '/';
  if (CONTROL_CHARS.test(next)) return '/';
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

/** الحالة العابرة قبل التحويل (الاحتراز الثاني في §١٠). */
export function newState() {
  return randomToken(32);
}

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

/** قراءة كوكي بالتقسيم لا بتعبير نمطي — اسم الكوكي لا يُقحَم في نمط. */
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
      return null;
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
