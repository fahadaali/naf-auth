// naf-auth — الوسيط
// يحمي كل مسارات المنصة، ويحوّل غير المسجَّل إلى المركز، ويحقن المستخدم في السياق.

import { newState, readCookie, safeNext, sessionCookie } from './safe.js';
import { getMember } from './store.js';

/**
 * أي مسار جديد محمي افتراضياً (§٦-١).
 * فالمطابقة صريحة: مساواة تامة، أو بادئة مُعلنة في `publicPrefixes`.
 * لا أنماط عامة ولا اجتهاد على الامتداد — إضافة مسار عام قرار مكتوب.
 */
export function isPublicPath(pathname, config) {
  if (config.publicPaths.includes(pathname)) return true;
  return config.publicPrefixes.some((prefix) => pathname.startsWith(prefix));
}

function redirect(location, headers = {}) {
  return new Response(null, { status: 302, headers: { location, ...headers } });
}

/** تحويل إلى صفحة الرفض برمز سبب أو بنصّ قادم من المركز. */
export function deniedResponse(config, reason) {
  const url = `${config.deniedPath}?r=${encodeURIComponent(reason)}`;
  return redirect(url);
}

/**
 * بدء الدخول: تُولَّد الحالة وتُخزَّن مع الوجهة قبل التحويل (الاحتراز الثاني في §١٠).
 * الوجهة تُحفظ في `KV` لا في الرابط وحده، فما يُطابَق عند العودة هو المخزَّن.
 */
export async function startLogin(request, env, config) {
  const url = new URL(request.url);
  const state = newState();
  const next = safeNext(url.pathname + url.search);

  await config.kv(env).put(`st:${state}`, JSON.stringify({ next }), {
    expirationTtl: config.stateTtlSeconds,
  });

  const target = new URL(`${config.issuer.replace(/\/+$/, '')}/go/${config.platformId}`);
  target.searchParams.set('next', next);
  target.searchParams.set('state', state);

  return redirect(target.toString());
}

/**
 * جوهر الوسيط. يعيد إمّا `Response` جاهزاً (تحويل أو رفض)، وإمّا `{ user }`.
 * لا يكتب في الاستجابة بنفسه ليصلح لـ Pages Functions ولـ Worker على حدّ سواء.
 */
export async function authenticate(request, env, config) {
  const url = new URL(request.url);

  if (isPublicPath(url.pathname, config)) return { public: true };

  const sid = readCookie(request, config.cookieName);
  if (!sid) return { response: await startLogin(request, env, config) };

  const session = await config.kv(env).get(`sess:${sid}`, 'json');

  // §٦-٣: الجلسة المنتهية تعود إلى المركز ولا تجدّد نفسها،
  // وإلا بقي الموقوف مركزياً يدخل حتى انتهاء كوكيه.
  if (!session || !session.sub) {
    return { response: await startLogin(request, env, config) };
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

export { sessionCookie };
