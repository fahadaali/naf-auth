// naf-auth — الخروج
// يُنهي جلسة المنصة، ثم يُخرج المتصفّح منها إلى شبكة المنصات في المركز.

import { clearCookie, readCookie } from './safe.js';
import { wantsDocument } from './middleware.js';

/**
 * وجهة الخارج: شبكة المنصات في المركز، لا جذر هذه المنصة.
 *
 * وهذا هو بيت العطل كلّه. الخروج محليّ — يُنهي جلسة هذه المنصة ولا يمسّ جلسة
 * المركز، وهذا هو المقصود — لكن إعادة الخارج إلى `‎/` تُدخله من جديد في الحال:
 * الجذر محميّ، فيحوّله الوسيط إلى `‎/go/:id`، وجلسة المركز قائمة، فيصدر رمزٌ
 * ويعود المستخدم إلى الشاشة التي خرج منها قبل أن يقرأ شيئاً.
 *
 * فيقرأ المستخدم من هذه الدورة أن الزرّ لا يعمل، وهو يعمل — والعائد أن
 * الوجهة كانت داخل السياج لا خارجه.
 *
 * والوجهة المركز لا صفحةَ وداعٍ محلية: من خرج من منصة أراد إمّا أن يغادر
 * وإمّا أن ينتقل إلى أخرى، وكلاهما في الشبكة.
 */
export function logoutTarget(config) {
  return `${config.issuer}/`;
}

/**
 * الخروج من هذه المنصة.
 *
 * تُحذف الجلسة من `KV` أولاً ثم يُمسح الكوكي. والحذف هو الخروج فعلاً: الكوكي
 * الممسوح يبقى صالحاً عند من نسخ قيمته قبل الخروج، والمفتاح المحذوف لا.
 *
 * وشكل الردّ يتبع طبيعة الطلب كما يتبعها في الوسيط:
 *   تنقّلٌ يعرض صفحة  → ٣٠٢ إلى المركز
 *   نداءُ `fetch`      → ٢٠٠ ومعه الوجهة في `next`
 *
 * والفرع الثاني ليس ترفاً: المتصفّح لا يتبع تحويلةً إلى أصل آخر في نداء
 * `fetch` بلا ترويسات `CORS` — يسقط الطلب بخطأ شبكة، فتبقى اللوحة مكانها
 * وقد أُغلقت جلستها تحتها. فتُعطى الوجهةُ نصّاً لتنتقل إليها بنفسها.
 *
 * ولا يُبطَل شيء في المركز من هنا: جلسة المركز شأنه، وإنهاؤها من منصة يُخرج
 * المستخدم من المنصات الأربع الأخرى وهو لم يطلب ذلك.
 *
 * ويعيد `Response` دائماً — ولا يرمي: من فشل حذف مفتاحه يجب أن يخرج كذلك،
 * وجلسته تنتهي بانتهاء عمرها القصير على أبعد تقدير.
 */
export async function handleLogout(request, env, config) {
  const sid = readCookie(request, config.cookieName);

  if (sid) {
    try {
      await config.kv(env).delete(`sess:${sid}`);
    } catch (err) {
      if (config.onError) config.onError('logout_delete_failed', err);
    }
  }

  const next = logoutTarget(config);
  const headers = {
    'set-cookie': clearCookie(config.cookieName),
    'cache-control': 'no-store',
  };

  if (wantsDocument(request, new URL(request.url), config)) {
    return new Response(null, { status: 302, headers: { ...headers, location: next } });
  }

  return new Response(JSON.stringify({ ok: true, next }), {
    status: 200,
    headers: { ...headers, 'content-type': 'application/json; charset=utf-8' },
  });
}

/** غلاف Pages Functions — يُستعمل في `functions/auth/logout.js`. */
export function pagesLogout(config) {
  return async (context) => handleLogout(context.request, context.env, config);
}
