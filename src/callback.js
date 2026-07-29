// naf-auth — مسار الاستقبال
// يستقبل رمز العبور، يبادله خادماً لخادم، ينشئ العضو، ثم يفتح جلسة المنصة.

import {
  AuthError,
  newSessionId,
  readCookie,
  safeNext,
  sessionCookie,
  sha256Hex,
  timingSafeEqual,
} from './safe.js';
import { bindCookieName, deniedResponse, startLogin } from './middleware.js';
import { upsertMember } from './store.js';
import { verifyToken } from './verify.js';

/**
 * عمر الجلسة = ما بقي من عمر الرمز.
 *
 * الرمز يعيش خمس عشرة دقيقة، وقِصَره هو ما يجعل الإيقاف المركزي يسري خلال
 * ربع ساعة. فجلسةٌ أطول منه تُبطل هذه الخاصية بالضبط: يبقى الموقوف مركزياً
 * داخلاً حتى ينتهي كوكيه لا حتى ينتهي رمزه.
 *
 * و`KV` لا يقبل عمراً أقلّ من ستين ثانية.
 */
function sessionTtl(exp) {
  return Math.max(60, exp - Math.floor(Date.now() / 1000));
}

/**
 * مهلة كل نداء إلى المركز.
 *
 * بلا مهلة يرث النداءُ مهلةَ الـWorker كلها: مركزٌ يقبل الاتصال ولا يردّ
 * يُعلّق الدخول حتى ينفد وقت الطلب، فيصل صاحبَه خطأُ منصّة لا خطأُ دخول —
 * وقد تمّت مصادقتُه فعلاً. والمركز نفسه يضع ثلاث ثوانٍ على نداء الخروج
 * الخلفي، وهذه الجهة أولى بها.
 */
const CENTER_TIMEOUT_MS = 5000;

/**
 * مبادلة رمز العبور بالرمز الموقّع — خادماً لخادم.
 *
 * أسماء الحقول هي أسماء المركز حرفياً: `platformId` و `secret` و `code`
 * و `state`. والمركز يفحص أنواعها الأربعة نصوصاً ويردّ `invalid_body` على
 * أي اختلاف — فاسم حقل واحد بصيغة أخرى يُسقط كل دخول في المنصة، ويفشل
 * فشلاً لا يفرّق بينه وبين سرّ خاطئ.
 *
 * والسرّ لا يغادر هذه الدالة، ولا يدخل رسالة خطأ ولا سجلّاً.
 *
 * `state` يُعاد كما وصل من المركز لا كما ولّدناه: المركز هو من يولّده
 * ويخزّنه مع الرمز، ويطابق الاثنين عند المبادلة.
 */
async function exchangeCode(code, state, env, config) {
  const secret = env[config.secretBinding];
  if (!secret) throw new AuthError('secret_missing');

  let res;
  try {
    res = await fetch(`${config.issuer}/api/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        platformId: config.platformId,
        secret,
        code,
        state,
      }),
      signal: AbortSignal.timeout(CENTER_TIMEOUT_MS),
    });
  } catch {
    // انقطاعٌ أو نفادُ مهلة — ولا يُرفق سببٌ تقني، فالرمز يكفي للسجلّ.
    throw new AuthError('exchange_unreachable');
  }

  if (!res.ok) {
    // نصّ الاستجابة لا يُرفَق: قد يعيد المركز ما أُرسل إليه.
    throw new AuthError('exchange_failed', `المركز رفض المبادلة (${res.status})`);
  }

  const body = await res.json().catch(() => null);
  if (!body || typeof body.token !== 'string' || !body.token) {
    throw new AuthError('exchange_malformed');
  }

  // الوجهة تعود في ردّ المبادلة. وتُنقّى هنا مرة أخرى: أن المركز فحصها لا
  // يُغني عن فحصنا، فنحن من يضعها في ترويسة `Location`.
  return {
    token: body.token,
    next: safeNext(body.next),
    // تجزئةُ سرّ الربط كما خزّنها المركز مع الرمز. `null` تعني أن الرمز
    // صدر بلا ربط — انظر `checkBinding`.
    bind: typeof body.bind === 'string' && body.bind ? body.bind : null,
  };
}

/**
 * تبليغ المركز بصلاحية الداخل — عرضاً لا حكماً، ولا يُسقط دخولاً.
 *
 * والعضو يُعرَّف بالبريد: جدول الوصول في المركز يُطابَق به لا بالمعرّف
 * المركزي. فمن لا بريد له في رمزه لا يُبلَّغ عنه — ولا يُخمَّن له بريد.
 *
 * ولا حالة في التبليغ: الدخول لا يغيّر منحاً ولا سحباً، وكتابة `granted`
 * مع كل دخول تمحو سحباً صادراً من المركز في اللحظة التي يليه فيها دخولٌ
 * برمزٍ أُصدر قبله.
 */
async function reportRoleOnLogin(env, config, claims, member) {
  const email = typeof claims.email === 'string' ? claims.email.trim() : '';
  const role = typeof member.role === 'string' ? member.role.trim() : '';
  if (!email || !role) return;

  try {
    await reportAccessChange(env, config, { email, role });
  } catch (err) {
    if (config.onError) config.onError('role_report_failed', err);
  }
}

/**
 * مطابقة الربط بالمتصفّح — ثلاث حالات لا رابعة، وكلُّها تنتهي.
 *
 * ١) المركز أعاد تجزئةً (`bind` نصّ):
 *    الرمز صدر مربوطاً، فيجب أن يحمل هذا المتصفّح سرَّه. تُطابَق تجزئةُ
 *    الكوكي بما عاد، مطابقةً ثابتة الزمن. وغيابُ الكوكي أو اختلافُه ردٌّ —
 *    وهو متصفّح الضحية في هجمة التثبيت.
 *
 * ٢) لا تجزئة عادت، وعندنا كوكي:
 *    أرسلنا ربطاً ولم يُعِده المركز — أي مركزٌ أقدم من هذه الحزمة. يُقبل
 *    الدخول كما كان قبل الربط، فلا تنكسر منصةٌ سبقت المركزَ في الترقية.
 *
 * ٣) لا تجزئة ولا كوكي:
 *    دخولٌ بدأ من شبكة المركز — بطاقةٌ تقصد `‎/go/:id` مباشرةً، فلم يمرّ
 *    بـ`startLogin` ولم يُولَّد له سرّ. فيُعاد البدء من هنا: `startLogin`
 *    يضع الكوكي ويرسل التجزئة، وجلسةُ المركز قائمة فيصدر رمزٌ جديد فوراً
 *    ويعود مربوطاً. ولفةٌ واحدة لا تتكرّر — لأن الرمز الجديد يحمل تجزئة،
 *    فالعودة تقع في الحالة (١) لا في (٣).
 *
 * ولا تلتقي الحالتان (٢) و(٣) في لفّةٍ لا تنتهي: (٣) تشترط غياب الكوكي،
 * و`startLogin` يضعه — فالدورة الثانية تجد كوكياً حتماً.
 */
async function checkBinding(request, config, bind) {
  const cookieName = bindCookieName(config);
  const nonce = readCookie(request, cookieName);

  if (bind) {
    if (!nonce) return 'missing';
    const matches = timingSafeEqual(await sha256Hex(nonce), bind);
    return matches ? 'ok' : 'mismatch';
  }

  return nonce ? 'legacy_center' : 'unbound';
}

/** كوكي الربط يُمحى بعد استعماله — لا يُترك حتى ينتهي عمره. */
function clearBindCookie(config) {
  return `${bindCookieName(config)}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

/**
 * مسار الاستقبال.
 *
 * لا حالة عابرة محلية: المركز يولّد `state` ويخزّنه مع رمز العبور، ثم
 * يطابق الاثنين عند المبادلة ويرفض عند الاختلاف. فحالةٌ ثانية من طرفنا
 * لا يعرفها المركز ولا يعيدها لا تضيف تحقّقاً — تُسقط الدخول وحسب.
 *
 * ورمز العبور يُستهلك مرة واحدة خلال ستين ثانية، فلا إعادة محاولة به:
 * محاولةٌ ثانية بالرمز نفسه تفشل حتماً.
 *
 * يعيد `Response` دائماً.
 */
export async function handleCallback(request, env, config) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  /* بلا رمز: أعد التحويل إلى المركز — زائرٌ بلغ المسار مباشرةً لا عائدٌ منه.

     والوجهة الجذر لا هذا المسار، وإلا دارت دورةٌ لا تنتهي:

       ١) زائرٌ يبلغ `‎/auth/callback` بلا رمز
       ٢) فيُحوَّل إلى `‎{issuer}/go/:id?next=/auth/callback`
       ٣) فيصدر المركز رمزاً ويعيده إلى `platform.url` — وهي هذا المسار
          نفسه — ومعه `next=/auth/callback`
       ٤) فتتمّ المبادلة وتُفتح الجلسة، ثم يُحوَّل إلى `next` أي إلى
          `‎/auth/callback` بلا رمز
       ٥) فيعود إلى (١)

     والمتصفّح يقطعها بـ`ERR_TOO_MANY_REDIRECTS` — لا برسالة تقول ما جرى.
     ويقع فعلاً: رابطٌ محفوظ في المفضّلة، أو عودةٌ بزرّ الرجوع بعد دخول تمّ.

     ومسار الاستقبال ليس وجهةً في أي حال: هو محطّة لا صفحة. */
  if (!code) {
    const root = new URL(request.url);
    root.pathname = '/';
    root.search = '';
    return startLogin(new Request(root, request), env, config);
  }

  // بلا حالة لا مبادلة: المركز يرسلهما معاً، وغيابها يعني رابطاً مركّباً.
  if (!state) return deniedResponse(request, config, config.reasons.badState);

  try {
    const { token, next: exchangedNext, bind } = await exchangeCode(code, state, env, config);

    /* الربط يُفحص قبل أي أثر يُترك: قبل التحقق من الرمز وقبل إنشاء العضو
       وقبل فتح الجلسة. فمحاولةُ تثبيتٍ لا تُنشئ صفّاً ولا تكتب مفتاحاً. */
    const binding = await checkBinding(request, config, bind);

    if (binding === 'missing' || binding === 'mismatch') {
      if (config.onError) config.onError(`bind_${binding}`, new AuthError(`bind_${binding}`));
      const denied = deniedResponse(request, config, config.reasons.badState);
      // ويُمحى الكوكي: سرٌّ أُخفق في مطابقته لا يُعاد استعماله.
      denied.headers.append('set-cookie', clearBindCookie(config));
      return denied;
    }

    if (binding === 'unbound') {
      /* دخولٌ بدأ من شبكة المركز. يُعاد البدء ليُولَّد له سرّ ربط — لفّةٌ
         واحدة، وجلسةُ المركز قائمة فلا يرى صاحبُها إلا تحويلتين.

         والبدء يقع من **الوجهة المقصودة** لا من مسار الاستقبال:
         `startLogin` يشتقّ `next` من عنوان الطلب الذي يصله، وعنوانُ هذا
         الطلب هو `‎/auth/callback?code=…` برمزٍ استُهلك توّاً. فلو مرّرناه
         كما هو لعادت الوجهة إليه، فيُحوَّل صاحبُه بعد دخولٍ تمّ إلى مسار
         استقبالٍ برمزٍ ميّت — فيفشل ويقرأ رفضاً بلا سبب.

         فيُبنى طلبٌ عنوانُه الوجهة: ما وصل في `next` إن كان سليماً، وإلا
         الجذر. ومسارُ الاستقبال ليس وجهةً في أي حال — هو محطّة لا صفحة. */
      const intended = safeNext(url.searchParams.get('next'));
      const restart = new URL(request.url);
      restart.search = '';
      if (intended !== '/' && !intended.startsWith(url.pathname)) {
        const parsed = new URL(intended, url.origin);
        restart.pathname = parsed.pathname;
        restart.search = parsed.search;
      } else {
        restart.pathname = '/';
      }

      return startLogin(new Request(restart, request), env, config);
    }

    // التحقق الكامل: التوقيع و `iss` و `aud` و `exp` معاً.
    const claims = await verifyToken(token, env, config);

    // نقطة تعليق بين التحقق والإدراج. منصة لها نظام أعضاء قائم تطابق هنا
    // العضو القادم بسجلّه المحلي قبل أن يُنشأ سجلّ ثانٍ له بالخطأ.
    if (config.onClaims) await config.onClaims(claims, env, config);

    const member = await upsertMember(env, config, claims);

    // الموقوف محلياً يُحوَّل إلى الرفض ولا تُفتح له جلسة.
    if (!member || !member.isActive) {
      return deniedResponse(request, config, config.reasons.inactive);
    }

    /* ═══ الدخول يبلّغ المركز بالصلاحية ═══

       بدون هذا السطر يبقى عمود الصلاحية في لوحة المركز فارغاً إلى الأبد.

       التبليغ كان في مسارات إدارة الأعضاء وحدها — منحٌ أو سحبٌ أو ترقية —
       وكلها أفعال مسؤولٍ لا أفعال عضو. فعضوٌ يدخل المنصة كل يوم ولا يمسّ
       أحدٌ دورَه لا يُبلَّغ عنه شيء، وتقرأ اللوحة عنه «لم يدخل المنصة بعد»
       وهو داخلها. والخانة تكذب، ومسؤول النظام يقرأ الكذبة على أنها عطل.

       وموضعه هنا لا في المنصات: خمسٌ تكتبه خمس مرات، وأولها ينساه.

       ويُنتظر ولا يُطلق: مسار الاستقبال يبادل الرمز مع المركز أصلاً، فهذه
       زيارةٌ ثانية إلى المضيف نفسه — والدخول يقع مرّة في اثنتي عشرة ساعة
       لا مرّة في كل طلب.

       وتعذّره لا يُسقط الدخول: العضو دخل، والناقص سطرٌ في لوحةٍ لا يراها.
       فيُسجَّل ويمضي.

       وموضعه بعد كتابة الجلسة لا قبلها: هو تبليغٌ للعرض وحده، وتقديمُه على
       ما يُثبت الدخول يجعل تعثّرَ لوحةٍ لا يراها المستخدم يكلّفه دخوله —
       فبين التبليغ وكتابة الجلسة تقع مهلةُ الشبكة كاملةً، وقد تنفد مهلةُ
       الـWorker قبل أن يُكتب شيء. فيُكتب أولاً ما لا يُستغنى عنه. */

    // جلسة بمعرّف عشوائي، تحمل الرمز الموقّع نفسه: الوسيط يعيد التحقق منه
    // في كل طلب محمي، فلا تكون الجلسة أطول عمراً من الرمز الذي أنشأها.
    const ttl = sessionTtl(claims.exp);
    const sid = newSessionId();
    await config.kv(env).put(
      `sess:${sid}`,
      JSON.stringify({ sub: claims.sub, token, exp: claims.exp }),
      { expirationTtl: ttl },
    );

    /* ودليلٌ من العضو إلى جلساته.
       `sess:{sid}` مفتاحٌ لا يُستدلّ عليه بصاحبه، وهو الصواب — معرّف الجلسة
       سرٌّ لا يُشتقّ من معرّف عضو. لكنّ الخروج من المركز يحتاج أن يجد جلسات
       فلانٍ في هذه المنصة ليمحوها، ولا سبيل إلى ذلك بلا دليل.
       فيُكتب مفتاحٌ فارغ اسمه يحمل الطرفين، وعمره عمر الجلسة نفسه فيذهب
       معها ولا يتراكم. */
    await config.kv(env).put(`usr:${claims.sub}:${sid}`, '1', { expirationTtl: ttl });

    // الجلسة صارت ثابتة. والتبليغ بعدها — انظر شرحه فوق.
    await reportRoleOnLogin(env, config, claims, member);

    // الوجهة تصل في الرابط وتعود في ردّ المبادلة. ما في الرابط أولى لأنه
    // ما طلبه هذا المتصفّح، وردّ المبادلة احتياطُه.
    const fromUrl = safeNext(url.searchParams.get('next'));
    const resolved = fromUrl === '/' ? exchangedNext : fromUrl;

    /* ووجهةٌ تشير إلى مسار الاستقبال تُردّ إلى الجذر.
       هو محطّة لا صفحة: بلوغه بلا رمز يبدأ الدخول من أوّله، فالعودة إليه
       بعد دخولٍ تمّ تعيد الكرّة بلا نهاية. والفحص هنا لا عند التوليد وحده
       لأن القيمة تعود من المركز كذلك. */
    const next = resolved === url.pathname ? '/' : resolved;

    /* كوكيّان في ردٍّ واحد: الجلسة تُفتح، وسرُّ الربط يُمحى — أدّى عمله.
       و`Headers` لا كائنٌ عادي: مفتاح `set-cookie` لا يتكرّر في كائن. */
    const headers = new Headers({ location: next, 'cache-control': 'no-store' });
    headers.append('set-cookie', sessionCookie(config.cookieName, sid, ttl));
    headers.append('set-cookie', clearBindCookie(config));

    return new Response(null, { status: 302, headers });
  } catch (err) {
    const errorCode = err instanceof AuthError ? err.code : 'callback_failed';
    if (config.onError) config.onError(errorCode, err);
    // الرسالة للمستخدم رمز ثابت، لا تفصيل تقني.
    return deniedResponse(request, config, config.reasons.authFailed);
  }
}

/** غلاف Pages Functions — يُستعمل في `functions/auth/callback.js`. */
export function pagesCallback(config) {
  return async (context) => handleCallback(context.request, context.env, config);
}

/**
 * التبليغ العكسي: عند إيقاف عضو من إعدادات المنصة يُبلَّغ المركز ليوافق
 * جدولُ الوصول ما تراه المنصة — وإلا بقيت بطاقتها تدعو المستخدم إلى باب
 * لا يفتح.
 *
 * والعضو يُعرَّف بالبريد لا بالمعرّف المركزي: المركز يطابق صفّه بالبريد.
 *
 * والمنصة تبلّغ عن نفسها لا عن غيرها — المركز يشتقّ المنصة من سرّها.
 */
export async function reportAccessChange(env, config, { email, state, reason, role }) {
  const secret = env[config.secretBinding];
  if (!secret) throw new AuthError('secret_missing');

  if (typeof email !== 'string' || !email.trim()) throw new AuthError('missing_email');

  const hasState = state !== undefined && state !== null;
  const hasRole = typeof role === 'string' && role.trim();

  // الحالتان المقبولتان مركزياً. وأي غيرهما يردّ المركز عليه `invalid_state`،
  // فيُمنع هنا قبل أن يحمل السرّ في طلب مرفوض.
  if (hasState && state !== 'granted' && state !== 'revoked') {
    throw new AuthError('bad_access_state');
  }
  // تبليغٌ لا يحمل حالةً ولا صلاحية لا يقول شيئاً — ويُمنع قبل أن يحمل السرّ.
  if (!hasState && !hasRole) throw new AuthError('empty_access_report');

  const body = {
    platformId: config.platformId,
    secret,
    email: email.trim(),
  };
  if (hasState) body.state = state;
  if (typeof reason === 'string' && reason.trim()) body.reason = reason.trim();

  /* الصلاحية داخل المنصة تُبلَّغ للعرض وحده.
     المصادقة مركزية والصلاحيات موزّعة، فالمركز لا يقرّر ما يملكه العضو هنا
     ولا يستطيع. لكنه كان يمنح وصولاً ولا يرى أثره: مسؤول النظام يمنح، ثم
     لا تقول له أي شاشة ماذا صار يرى الممنوح. فتُرسل المنصة ما قرّرته لتعرضه
     لوحة المركز — قراءةً لا حكماً، ولا يُقرأ في أي قرار دخول. */
  if (hasRole) body.role = role.trim();

  let res;
  try {
    res = await fetch(`${config.issuer}/api/internal/access`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(CENTER_TIMEOUT_MS),
    });
  } catch {
    throw new AuthError('access_report_unreachable');
  }

  if (!res.ok) throw new AuthError('access_report_failed', `تعذّر تبليغ المركز (${res.status})`);
  return true;
}
