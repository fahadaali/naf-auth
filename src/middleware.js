// naf-auth — الوسيط
// يحمي كل مسارات المنصة، ويحوّل غير المسجَّل إلى المركز، ويحقن المستخدم في السياق.

import {
  AuthError,
  bindCookie,
  randomToken,
  readCookie,
  safeNext,
  sessionKeyFor,
  sha256Hex,
  userIndexKeyFor,
} from './safe.js';
import { getMember } from './store.js';
import { isTokenError, verifyToken } from './verify.js';

/**
 * أي مسار جديد محمي افتراضياً.
 * فالمطابقة صريحة: مساواة تامة، أو بادئة مُعلنة في `publicPrefixes`.
 * لا أنماط عامة ولا اجتهاد على الامتداد — إضافة مسار عام قرار مكتوب.
 */
export function isPublicPath(pathname, config) {
  if (config.publicPaths.includes(pathname)) return true;
  return config.publicPrefixes.some((prefix) => pathname.startsWith(prefix));
}

/** بادئة مسار مُعلنة كواجهة برمجية — تُستعمل حين لا يقول الطلب طبيعته. */
function isApiPath(pathname, config) {
  return config.apiPrefixes.some((prefix) => pathname.startsWith(prefix));
}

/**
 * هل هذا تنقّلٌ يعرض صفحة، أم نداءٌ برمجي ينتظر جسماً يُقرأ؟
 *
 * السؤال يتكرّر في كل ردّ يمنع المرور، والجواب يحدّد شكل الردّ: تحويلة
 * لمن يتنقّل، ورمزُ حالة وجسمٌ لمن ينادي من كود.
 *
 * والحكم بطبيعة الطلب لا ببادئة مساره. البادئة تخطئ في حالة قائمة فعلاً:
 * رابط تنزيلٍ تحت `‎/api/` تنقّلٌ من المستخدم، وردُّ `JSON` عليه يعرض عليه
 * نصّاً خاماً مكان أن يعيده إلى الدخول. والعكس يقع كذلك — نداءُ `fetch`
 * إلى مسارٍ خارج البادئات يأخذ تحويلةً لا يتبعها.
 *
 * والترتيب: `Sec-Fetch-Mode` أوّلاً — يقولها المتصفّح صراحةً — ثم `Accept`.
 * فإن خلا الطلب منهما معاً (عميل لا يرسل ترويسات) رجعنا إلى `apiPrefixes`،
 * وهي آخر ما يُسأل لا أوّله.
 */
export function wantsDocument(request, url, config) {
  const mode = request.headers.get('sec-fetch-mode');
  if (mode) return mode === 'navigate';

  const accept = request.headers.get('accept');
  if (accept) return accept.includes('text/html');

  return !isApiPath(url.pathname, config);
}

function jsonResponse(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function redirect(location, headers = {}) {
  return new Response(null, {
    status: 302,
    headers: { location, 'cache-control': 'no-store', ...headers },
  });
}

/**
 * الرفض برمز سبب أو بنصّ قادم من المركز.
 *
 * ولا يُحوَّل نداءٌ برمجي إلى `‎/denied`: التحويلة هنا **داخلية**، فيتبعها
 * `fetch` بنجاح ويستقبل صفحة الواجهة نصّاً، فيسقط تحليل `JSON` عند اللوحة
 * بخطأٍ لا صلة له بالسبب. فيقرأ العضو الموقوف «خطأ في التحليل» مكان مصطلح
 * الرفض المسجَّل — وهي حالٌ تقع فعلاً: الرفض لا يأتي عند الدخول بل في أوّل
 * طلب تالٍ لعضوٍ أُوقف ولوحتُه مفتوحة.
 *
 * والسبب يبقى رمزاً لا جملة: ترجمته إلى المصطلح المسجَّل عمل صفحة `‎/denied`.
 */
export function deniedResponse(request, config, reason) {
  const path = `${config.deniedPath}?r=${encodeURIComponent(reason)}`;
  const url = new URL(request.url);
  if (!wantsDocument(request, url, config)) {
    return jsonResponse({ ok: false, error: 'access_denied', reason, denied: path }, 403);
  }
  return redirect(path);
}

/**
 * عنوان باب المركز لهذه المنصة، ومعه الوجهة المطلوبة.
 *
 * والوجهة تُعلَّق للتنقّل وحده. مسارُ نداءٍ برمجي لا يصلح وجهةَ عودة: من
 * ردّت لوحتُه على `‎/api/me` بـ٤٠١ ثم دخل بهذا الرابط يعود إلى `‎/api/me`
 * فيقرأ `JSON` خاماً مكان لوحته. والمسار الذي ردّ ليس الصفحةَ التي يقف
 * فيها صاحبه أصلاً — المتصفّح وحده يعرفها، فيعلّقها هو على `login` العائد
 * في الجسم.
 *
 * وهذا يقع في كل منصة: الرمز يعيش خمس عشرة دقيقة، ولوحةٌ مفتوحة أطول من
 * ذلك تبلغ هذا الردّ. وقد عولج في أربع لوحات على حدة قبل أن يُعالج هنا.
 */
function loginUrl(request, config) {
  const url = new URL(request.url);
  const target = new URL(`${config.issuer}/go/${encodeURIComponent(config.platformId)}`);
  if (wantsDocument(request, url, config)) {
    const next = safeNext(url.pathname + url.search);
    if (next !== '/') target.searchParams.set('next', next);
  }
  return target.toString();
}

/**
 * بدء الدخول: تحويلة إلى باب المركز، ومعها ربطٌ بهذا المتصفّح.
 *
 * `state` يولّده المركز ويطابقه عند المبادلة — وهو يثبت أن الرمز والحالة
 * جاءا معاً من المركز، **ولا يثبت شيئاً عن المتصفّح الواصل**: الاثنان
 * يسافران في التحويلة نفسها، فمن ملك أحدهما ملك الآخر.
 *
 * وهذه هي ثغرة تثبيت الجلسة: يفتح المهاجم `‎{issuer}/go/:id` في متصفّحه،
 * يلتقط `‎…/auth/callback?code=C&state=S` ولا يتبعه، ثم يدفع الضحية إليه
 * خلال الستين ثانية. فتتمّ المبادلة وتُفتح جلسةٌ بهوية **المهاجم** في
 * متصفّح **الضحية** — فترفع ملفاتها وتكتب مسوّداتها في حسابه، ويقرؤها
 * بدخوله العادي. و`SameSite=Lax` لا تمنع شيئاً: الوصول تنقّلٌ علويّ بـ`GET`.
 *
 * فيُولَّد هنا سرٌّ عشوائي يبقى في كوكي على هذا المتصفّح وحده، ولا يسافر:
 * الذي يسافر تجزئتُه. والمركز يخزّنها مع رمز العبور ويعيدها في ردّ
 * المبادلة، فيطابق مسارُ الاستقبال تجزئةَ الكوكي بما عاد. ومتصفّحُ الضحية
 * لا كوكي فيه، فتُردّ المحاولة.
 */
export async function startLogin(request, env, config) {
  const nonce = randomToken(32);
  const target = new URL(loginUrl(request, config));
  target.searchParams.set('bind', await sha256Hex(nonce));

  return redirect(target.toString(), {
    'set-cookie': bindCookie(bindCookieName(config), nonce),
  });
}

/** اسم كوكي الربط — مشتقٌّ من اسم كوكي الجلسة فلا يصطدم بمنصةٍ أخرى. */
export function bindCookieName(config) {
  return `${config.cookieName}_bind`;
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
  return jsonResponse({ ok: false, error: 'unauthorized', login: loginUrl(request, config) }, 401);
}

/**
 * ردّ «تعذّر التحقق الآن» — والجلسة باقية.
 *
 * يُستعمل حين يعجز المتحقّق لا حين يبطل الرمز: المركز متعثّر أو الشبكة
 * منقطعة. و٥٠٣ لا ٤٠١ لأن الأول يقول «أعِد المحاولة» والثاني يقول «سجّل
 * الدخول» — والثاني كذبٌ هنا يدفع صاحبه إلى بابٍ لا يفتح.
 *
 * و`Retry-After` ثانيتان: عطلُ الجلب لحظيّ في الغالب، والمخبأ يعود بأول
 * جلبٍ ناجح.
 *
 * والردّ واحدٌ للتنقّل ولنداء `fetch` معاً — بخلاف بقية ردود هذا الملف:
 * ليس في الحالين وجهةٌ تنفع. التحويلة إلى المركز تُرسل صاحبها إلى المضيف
 * المتعثّر نفسه، فالصدق أن يُقال «أعِد المحاولة» لا أن يُدار في حلقة.
 */
function unavailableResponse() {
  return new Response(JSON.stringify({ ok: false, error: 'auth_unavailable' }), {
    status: 503,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'retry-after': '2',
    },
  });
}

/**
 * جوهر الوسيط. يعيد إمّا `Response` جاهزاً (تحويل أو رفض)، وإمّا `{ user }`.
 * لا يكتب في الاستجابة بنفسه ليصلح لـ Pages Functions ولـ Worker على حدّ سواء.
 */
export async function authenticate(request, env, config) {
  const url = new URL(request.url);

  if (isPublicPath(url.pathname, config)) return { public: true };

  /* التنقّل يمرّ بـ`startLogin` لا بتحويلةٍ مباشرة: هو الذي يولّد سرّ الربط
     ويضعه في كوكي ويرسل تجزئته. وهذا هو المدخل الغالب — الرمز يعيش خمس عشرة
     دقيقة، فكل لوحةٍ مفتوحة أطول من ذلك تمرّ من هنا.

     أمّا نداء `fetch` فيأخذ ٤٠١ ومعه عنوان الباب كما كان: لا كوكي يُوضع في
     ردٍّ لا يتنقّل به المتصفّح، والتنقّل الذي يليه يبلغ المركز بلا ربط —
     فيلتقطه مسارُ الاستقبال ويعيد بدأه مربوطاً. */
  const noSession = async () =>
    wantsDocument(request, url, config)
      ? startLogin(request, env, config)
      : unauthorizedResponse(request, config);

  const sid = readCookie(request, config.cookieName);
  if (!sid) return { response: await noSession() };

  const kv = config.kv(env);
  const session = await kv.get(await sessionKeyFor(sid), 'json');

  // الجلسة المنتهية تعود إلى المركز ولا تجدّد نفسها، وإلا بقي الموقوف
  // مركزياً يدخل حتى انتهاء كوكيه.
  if (!session || !session.sub || !session.token) return { response: await noSession() };

  /* ═══ التحقق في كل طلب محمي، لا عند الاستقبال وحده ═══
     الرمز يعيش خمس عشرة دقيقة، وهذا الفحص هو ما يجعل لقِصَره معنى: بلا
     إعادة تحقّق تصير الجلسة المحلية هي الحقيقة، فيبقى من أُوقف مركزياً
     داخلاً ما بقي كوكيه. والتجديد يمرّ بالمركز لا هنا.

     ولا شبكة في المسار السويّ: المفاتيح مخبّأة في `KV`، فالكلفة قراءةُ
     مفتاح وتحقّقُ توقيع. */
  let claims;
  try {
    claims = await verifyToken(session.token, env, config);
  } catch (err) {
    if (config.onError) {
      config.onError(err instanceof AuthError ? err.code : 'session_verify_failed', err);
    }

    /* ═══ «الرمز باطل» ليس «عجزتُ عن الفحص» ═══

       الفرع الأول حكمٌ على الرمز: تُمسح الجلسة فلا تُقرأ ثانيةً، ويعود
       الطلب إلى المركز ليصدر رمزاً جديداً إن كان صاحبه لا يزال مخوَّلاً.

       والثاني حكمٌ على الشبكة لا على صاحبها: `jwks_unavailable` يقع حين
       يتعثّر المركز أو تنقطع الشبكة أو يُردّ الجلبُ بحدّ معدّل. ومحوُ
       الجلسة عندئذ يعاقب عضواً لم يُخطئ، ويرسله إلى المضيف المتعثّر نفسه
       ليدخل من جديد — فلا يعود بجلسة. فتُترك جلسته كما هي، ويُردّ ٥٠٣:
       الطلب التالي بعد تعافي المركز يمرّ بلا دخولٍ جديد.

       والمخبأ يعيش خمس دقائق، فنافذةُ الاعتماد على الشبكة تتكرّر كل خمس
       دقائق لكل منصة — وهي أكثر من أن تُترك لحكمٍ خاطئ. */
    if (!isTokenError(err)) return { response: unavailableResponse() };

    await kv.delete(await sessionKeyFor(sid));
    await kv.delete(await userIndexKeyFor(session.sub, sid));
    return { response: await noSession() };
  }

  const member = await getMember(env, config, session.sub);
  if (!member) return { response: deniedResponse(request, config, config.reasons.notMember) };
  if (!member.isActive) {
    return { response: deniedResponse(request, config, config.reasons.inactive) };
  }

  // `claims` معها: تحقّقنا منها في هذا الطلب نفسه، ومنصةٌ تحتاج البريد أو
  // الاسم تأخذهما من هنا بدل أن تفكّ الرمز بنفسها بلا تحقّق.
  return {
    user: { id: member.id, role: member.role, perms: member.perms },
    claims,
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
