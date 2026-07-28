// naf-auth — مسار الاستقبال
// يستقبل رمز العبور، يبادله خادماً لخادم، ينشئ العضو، ثم يفتح جلسة المنصة.

import { AuthError, newSessionId, safeNext, sessionCookie } from './safe.js';
import { deniedResponse, startLogin } from './middleware.js';
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

  const res = await fetch(`${config.issuer}/api/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      platformId: config.platformId,
      secret,
      code,
      state,
    }),
  });

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
  return { token: body.token, next: safeNext(body.next) };
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
    const { token, next: exchangedNext } = await exchangeCode(code, state, env, config);

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

    // جلسة بمعرّف عشوائي، تحمل الرمز الموقّع نفسه: الوسيط يعيد التحقق منه
    // في كل طلب محمي، فلا تكون الجلسة أطول عمراً من الرمز الذي أنشأها.
    const ttl = sessionTtl(claims.exp);
    const sid = newSessionId();
    await config.kv(env).put(
      `sess:${sid}`,
      JSON.stringify({ sub: claims.sub, token, exp: claims.exp }),
      { expirationTtl: ttl },
    );

    // الوجهة تصل في الرابط وتعود في ردّ المبادلة. ما في الرابط أولى لأنه
    // ما طلبه هذا المتصفّح، وردّ المبادلة احتياطُه.
    const fromUrl = safeNext(url.searchParams.get('next'));
    const resolved = fromUrl === '/' ? exchangedNext : fromUrl;

    /* ووجهةٌ تشير إلى مسار الاستقبال تُردّ إلى الجذر.
       هو محطّة لا صفحة: بلوغه بلا رمز يبدأ الدخول من أوّله، فالعودة إليه
       بعد دخولٍ تمّ تعيد الكرّة بلا نهاية. والفحص هنا لا عند التوليد وحده
       لأن القيمة تعود من المركز كذلك. */
    const next = resolved === url.pathname ? '/' : resolved;

    return new Response(null, {
      status: 302,
      headers: {
        location: next,
        'set-cookie': sessionCookie(config.cookieName, sid, ttl),
        'cache-control': 'no-store',
      },
    });
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

  const res = await fetch(`${config.issuer}/api/internal/access`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) throw new AuthError('access_report_failed', `تعذّر تبليغ المركز (${res.status})`);
  return true;
}
