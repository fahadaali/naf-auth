// naf-auth — مسار الاستقبال
// يستقبل رمز العبور، يبادله خادماً لخادم، ينشئ العضو، ثم يفتح جلسة المنصة.

import { AuthError, newSessionId, safeNext, sessionCookie, timingSafeEqual } from './safe.js';
import { deniedResponse, startLogin } from './middleware.js';
import { upsertMember } from './store.js';
import { verifyToken } from './verify.js';

/**
 * مبادلة رمز العبور بالرمز الموقّع — خادماً لخادم (الخطوة ٣ في §٦-٢).
 * السرّ لا يغادر هذه الدالة، ولا يدخل رسالة خطأ ولا سجلّاً (الاحتراز الثالث في §١٠).
 */
async function exchangeCode(code, env, config) {
  const secret = env[config.secretBinding];
  if (!secret) throw new AuthError('secret_missing');

  const res = await fetch(`${config.issuer}/api/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      code,
      client_id: config.platformId,
      client_secret: secret,
    }),
  });

  if (!res.ok) {
    // نصّ الاستجابة لا يُرفَق: قد يعيد المركز ما أُرسل إليه.
    throw new AuthError('exchange_failed', `المركز رفض المبادلة (${res.status})`);
  }

  const body = await res.json().catch(() => null);
  const token = body && (body.token || body.id_token || body.access_token);
  if (!token) throw new AuthError('exchange_malformed');
  return token;
}

/**
 * مسار الاستقبال بالترتيب المنصوص في §٦-٢.
 * يعيد `Response` دائماً.
 */
export async function handleCallback(request, env, config) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  // ١ — بلا رمز: أعد التحويل إلى المركز.
  if (!code) return startLogin(request, env, config);

  // ٢ — طابق الحالة مع المخزَّن واحذفه. بلا مطابقة يُرفض الطلب.
  if (!state) return deniedResponse(config, config.reasons.badState);

  const kv = config.kv(env);
  const storedRaw = await kv.get(`st:${state}`);
  if (!storedRaw) return deniedResponse(config, config.reasons.badState);
  await kv.delete(`st:${state}`);

  let stored;
  try {
    stored = JSON.parse(storedRaw);
  } catch {
    return deniedResponse(config, config.reasons.badState);
  }

  // المفتاح نفسه هو الحالة، فوجوده مطابقة. والمقارنة الصريحة تبقى
  // احتياطاً لو غُيّر التخزين لاحقاً ليحمل الحالة داخل القيمة.
  if (stored.state && !timingSafeEqual(stored.state, state)) {
    return deniedResponse(config, config.reasons.badState);
  }

  let claims;
  try {
    // ٣ — المبادلة، ٤ — التحقق الكامل: التوقيع و iss و aud و exp معاً.
    const token = await exchangeCode(code, env, config);
    claims = await verifyToken(token, env, config);

    // ٥ — أدرج العضو أو حدّثه.
    const member = await upsertMember(env, config, claims);

    // ٦ — الموقوف يُحوَّل إلى الرفض ولا تُفتح له جلسة.
    if (!member || !member.isActive) {
      return deniedResponse(config, config.reasons.inactive);
    }

    // ٧ — جلسة بمعرّف عشوائي، فيها `sub` والرمز الموقّع.
    const sid = newSessionId();
    await kv.put(
      `sess:${sid}`,
      JSON.stringify({ sub: claims.sub, token, createdAt: Math.floor(Date.now() / 1000) }),
      { expirationTtl: config.sessionTtlSeconds },
    );

    // ٨ — التحويل إلى الوجهة بعد تنقيتها، مع كوكي الجلسة.
    const next = safeNext(stored.next);
    return new Response(null, {
      status: 302,
      headers: {
        location: next,
        'set-cookie': sessionCookie(config.cookieName, sid, config.sessionTtlSeconds),
      },
    });
  } catch (err) {
    const errorCode = err instanceof AuthError ? err.code : 'callback_failed';
    if (config.onError) config.onError(errorCode, err);
    // الرسالة للمستخدم رمز ثابت، لا تفصيل تقني (الاحتراز الثامن في §١٠).
    return deniedResponse(config, config.reasons.authFailed);
  }
}

/** غلاف Pages Functions — يُستعمل في `functions/auth/callback.js`. */
export function pagesCallback(config) {
  return async (context) => handleCallback(context.request, context.env, config);
}

/**
 * التبليغ العكسي (§٦-٤): عند إيقاف عضو من إعدادات المنصة يُبلَّغ المركز
 * ليظهر السبب للمستخدم في شبكته.
 */
export async function reportAccessChange(env, config, { userId, status, reason }) {
  const secret = env[config.secretBinding];
  if (!secret) throw new AuthError('secret_missing');

  const res = await fetch(`${config.issuer}/api/internal/access`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      client_id: config.platformId,
      client_secret: secret,
      user_id: userId,
      status,
      reason,
    }),
  });

  if (!res.ok) throw new AuthError('access_report_failed', `تعذّر تبليغ المركز (${res.status})`);
  return true;
}
