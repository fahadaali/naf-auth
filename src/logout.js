// naf-auth — الخروج
// يُنهي جلسة المنصة، ثم يُخرج المتصفّح منها إلى شبكة المنصات في المركز.

import { clearCookie, readCookie } from './safe.js';
import { wantsDocument } from './middleware.js';
import { verifyLogoutToken } from './verify.js';

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
      const kv = config.kv(env);
      // الجلسة تُقرأ قبل محوها ليُمحى دليلُها معها: مفتاحٌ يتيم في الدليل
      // يجعل خروجاً لاحقاً من المركز يبحث عن جلسة لم تعد موجودة.
      const session = await kv.get(`sess:${sid}`, 'json');
      await kv.delete(`sess:${sid}`);
      if (session && session.sub) await kv.delete(`usr:${session.sub}:${sid}`);
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

/**
 * إشعار الخروج الخلفي — المركز يُنهي جلسات عضوٍ في هذه المنصة.
 *
 * ═══ لماذا وُجد ═══
 *
 * الخروج من منصة محليّ عمداً: من خرج من المحاسب لم يطلب الخروج من الأربع
 * الأخرى. أمّا الخروج من **المركز** فهو الباب نفسه — ومن أغلق البابَ لا
 * يقبل أن تبقى غرفةٌ مفتوحة. وبلا هذا الإشعار تبقى جلسة كل منصة حيّة حتى
 * ينتهي رمزها، فيفتح صاحبُها رابط المنصة بعد خروجه من المركز فيدخل.
 *
 * ═══ لماذا رمزٌ موقّع لا سرّ مشترك ═══
 *
 * المركز يخزّن `secret_hash` لا السرّ، فلا يملك ما يوقّع به نفسه للمنصة —
 * السرّ يسير في الاتجاه الآخر وحده. لكنّه يملك مفتاح التوقيع الذي تعرفه كل
 * منصة أصلاً وتجلبه في `JWKS`. فالإشعار رمزٌ منه كرمز الدخول: `iss` نفسه
 * و`aud` معرّف هذه المنصة، ويفترق بـ`typ`. فلا سرّ جديد يُدار ولا ثقة
 * تُبنى من جديد.
 *
 * ═══ ولا يُحرَس هذا المسار بجلسة ═══
 *
 * صاحبه لا متصفّح له هنا: المركز ينادي خادماً لخادم. فالمسار عامّ في قائمة
 * الحارس، والتوقيع هو حراستُه — ورمزٌ بلا توقيع صحيح أو لمنصة أخرى يُردّ.
 *
 * ويردّ ٢٠٠ ومعه عدد ما أُنهي: صفرٌ ليس خطأ — عضوٌ لم يدخل هذه المنصة أصلاً
 * لا جلسة له فيها، والمركز ينادي الخمس جميعاً ولا يعرف أيّها دخل.
 */
export async function handleBackchannelLogout(request, env, config) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ ok: false, error: 'method_not_allowed' }), {
      status: 405,
      headers: { 'content-type': 'application/json; charset=utf-8', allow: 'POST' },
    });
  }

  let token = null;
  try {
    const body = await request.json();
    if (body && typeof body.logoutToken === 'string') token = body.logoutToken;
  } catch {
    // جسمٌ غير صالح يُعامل كرمزٍ مفقود — والرسالة واحدة في الحالين.
  }
  if (!token) return backchannelError(config, 'invalid_body', 400);

  let claims;
  try {
    claims = await verifyLogoutToken(token, env, config);
  } catch (err) {
    if (config.onError) config.onError('backchannel_logout_rejected', err);
    return backchannelError(config, 'invalid_token', 401);
  }

  const kv = config.kv(env);
  const prefix = `usr:${claims.sub}:`;

  /* ═══ تُجمع المفاتيح كلها أولاً، ثم تُمحى ═══

     الدليل يُقرأ صفحةً صفحة: `list` في KV محدود العدد، وعضوٌ فتح المنصة في
     أجهزة عدّة له جلسات عدّة. وترك آخرها لأن الصفحة الأولى امتلأت يُبقي
     الباب الذي جاء الإشعار ليغلقه.

     والمحو داخل الحلقة يفعل ذلك بالضبط: المؤشّر موضعٌ في ترتيب المفاتيح،
     فمحوُ الصفحة الأولى يزحزح ما بعدها إلى مواضع مضت — فتُقفز الصفحة
     التالية كلها. ثلاث جلسات وصفحةٌ من اثنتين تُنهي اثنتين وتُبقي واحدة،
     وهي التي سيدخل بها صاحبها. */
  const keys = [];
  let cursor;
  do {
    const page = await kv.list({ prefix, cursor });
    for (const key of page.keys) keys.push(key.name);
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);

  for (const name of keys) {
    await kv.delete(`sess:${name.slice(prefix.length)}`);
    await kv.delete(name);
  }

  return new Response(JSON.stringify({ ok: true, ended: keys.length }), {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function backchannelError(config, error, status) {
  return new Response(JSON.stringify({ ok: false, error }), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

/** غلاف Pages Functions لإشعار الخروج الخلفي. */
export function pagesBackchannelLogout(config) {
  return async (context) => handleBackchannelLogout(context.request, context.env, config);
}
