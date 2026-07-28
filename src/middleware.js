// naf-auth — الوسيط
// يحمي كل مسارات المنصة، ويحوّل غير المسجَّل إلى المركز، ويحقن المستخدم في السياق.

import { AuthError, readCookie, safeNext } from './safe.js';
import { getMember } from './store.js';
import { verifyToken } from './verify.js';

/**
 * أي مسار جديد محمي افتراضياً.
 * فالمطابقة صريحة: مساواة تامة، أو بادئة مُعلنة في `publicPrefixes`.
 * لا أنماط عامة ولا اجتهاد على الامتداد — إضافة مسار عام قرار مكتوب.
 */
export function isPublicPath(pathname, config) {
  if (config.publicPaths.includes(pathname)) return true;
  return config.publicPrefixes.some((prefix) => pathname.startsWith(prefix));
}

/** مسار واجهة برمجية: يُردّ عليه برمز حالة لا بتحويلة. */
function isApiPath(pathname, config) {
  return config.apiPrefixes.some((prefix) => pathname.startsWith(prefix));
}

function redirect(location, headers = {}) {
  return new Response(null, {
    status: 302,
    headers: { location, 'cache-control': 'no-store', ...headers },
  });
}

/** تحويل إلى صفحة الرفض برمز سبب أو بنصّ قادم من المركز. */
export function deniedResponse(config, reason) {
  return redirect(`${config.deniedPath}?r=${encodeURIComponent(reason)}`);
}

/** عنوان باب المركز لهذه المنصة، ومعه الوجهة المطلوبة. */
function loginUrl(request, config) {
  const url = new URL(request.url);
  const target = new URL(`${config.issuer}/go/${config.platformId}`);
  const next = safeNext(url.pathname + url.search);
  if (next !== '/') target.searchParams.set('next', next);
  return target.toString();
}

/**
 * بدء الدخول: تحويلة إلى باب المركز.
 *
 * ولا حالة عابرة تُولَّد هنا: `‎/go/:id` يتجاهل أي `state` يصله ويولّد
 * واحدة من عنده، فحالةٌ من طرفنا لا تعود إلينا أبداً — ومطابقتها عند
 * الاستقبال تفشل حتماً فتُسقط كل دخول.
 *
 * والوجهة تُحمل في الرابط: المركز يعلّقها على مسار الاستقبال عند التحويل،
 * ويعيدها ثانيةً في ردّ المبادلة.
 */
export async function startLogin(request, env, config) {
  return redirect(loginUrl(request, config));
}

/**
 * ردّ «لا جلسة» على طلب واجهة برمجية.
 *
 * تحويلةٌ إلى المركز لا تنفع طلب `fetch`: المتصفّح يتبعها إلى أصل آخر بلا
 * ترويسات `CORS`، فيفشل الطلب فشلاً شبكياً لا يقول للوحة أن تعيد الدخول.
 * والرمز ٤٠١ ومعه عنوان الباب يقولان ذلك صراحةً.
 *
 * وهذا يقع كثيراً لا نادراً: الرمز يعيش خمس عشرة دقيقة، ولوحةٌ مفتوحة
 * أطول من ذلك تبلغ هذا الردّ في كل مرة.
 */
function unauthorizedResponse(request, config) {
  return new Response(
    JSON.stringify({ ok: false, error: 'unauthorized', login: loginUrl(request, config) }),
    {
      status: 401,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    },
  );
}

/**
 * جوهر الوسيط. يعيد إمّا `Response` جاهزاً (تحويل أو رفض)، وإمّا `{ user }`.
 * لا يكتب في الاستجابة بنفسه ليصلح لـ Pages Functions ولـ Worker على حدّ سواء.
 */
export async function authenticate(request, env, config) {
  const url = new URL(request.url);

  if (isPublicPath(url.pathname, config)) return { public: true };

  const noSession = () =>
    isApiPath(url.pathname, config)
      ? unauthorizedResponse(request, config)
      : redirect(loginUrl(request, config));

  const sid = readCookie(request, config.cookieName);
  if (!sid) return { response: noSession() };

  const kv = config.kv(env);
  const session = await kv.get(`sess:${sid}`, 'json');

  // الجلسة المنتهية تعود إلى المركز ولا تجدّد نفسها، وإلا بقي الموقوف
  // مركزياً يدخل حتى انتهاء كوكيه.
  if (!session || !session.sub || !session.token) return { response: noSession() };

  /* ═══ التحقق في كل طلب محمي، لا عند الاستقبال وحده ═══
     الرمز يعيش خمس عشرة دقيقة، وهذا الفحص هو ما يجعل لقِصَره معنى: بلا
     إعادة تحقّق تصير الجلسة المحلية هي الحقيقة، فيبقى من أُوقف مركزياً
     داخلاً ما بقي كوكيه. والتجديد يمرّ بالمركز لا هنا.

     ولا شبكة في المسار السويّ: المفاتيح مخبّأة في `KV`، فالكلفة قراءةُ
     مفتاح وتحقّقُ توقيع. */
  try {
    await verifyToken(session.token, env, config);
  } catch (err) {
    if (config.onError) {
      config.onError(err instanceof AuthError ? err.code : 'session_verify_failed', err);
    }
    // رمزٌ لم يعد صالحاً: تُمسح الجلسة فلا تُقرأ ثانيةً، ويعود الطلب إلى
    // المركز ليصدر رمزاً جديداً إن كان صاحبه لا يزال مخوَّلاً.
    await kv.delete(`sess:${sid}`);
    return { response: noSession() };
  }

  const member = await getMember(env, config, session.sub);
  if (!member) return { response: deniedResponse(config, config.reasons.notMember) };
  if (!member.isActive) return { response: deniedResponse(config, config.reasons.inactive) };

  return {
    user: { id: member.id, role: member.role, perms: member.perms },
    session,
  };
}

/** غلاف Pages Functions — يُستعمل في `functions/_middleware.js`. */
export function pagesMiddleware(config) {
  return async (context) => {
    const result = await authenticate(context.request, context.env, config);
    if (result.response) return result.response;
    if (result.user) context.data.user = result.user;
    return context.next();
  };
}

/** غلاف Hono — بلا استيراد من hono، فالتبعية تبقى صفراً. */
export function honoMiddleware(config) {
  return async (c, next) => {
    const result = await authenticate(c.req.raw, c.env, config);
    if (result.response) return result.response;
    if (result.user) c.set('user', result.user);
    await next();
  };
}
