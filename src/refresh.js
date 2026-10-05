// naf-auth — التجديد الصامت
//
// الرمز الموقّع يعيش خمس عشرة دقيقة. وكان تجديده يمرّ بالمتصفح: الجلسة
// تنتهي بانتهائه، فيُحوَّل صاحبها إلى `/go/:id` ويعود. وهذا صامتٌ في
// التنقّل، لكنّ نداء `fetch` من شاشةٍ مفتوحة يأخذ ٤٠١ — فتُعاد الشاشة
// كلّها ويضيع ما عليها، كلّ ربع ساعة. وفي تطبيق الشاشة الرئيسية على آيفون
// تنفتح نافذةُ متصفّحٍ داخلي في كل مرّة.
//
// فيُصدر المركز مع الرمز الأول رمزَ تجديد يُحفظ في الجلسة هنا، على خادم
// المنصة، ولا يبلغ المتصفح أبداً. وحين ينتهي الرمز يُبادَل رمزُ التجديد
// في `POST {issuer}/api/refresh` بسرّ المنصة برمزٍ جديد، ويمضي الطلب.
//
// ═══ وما لم يتغيّر ═══
//
// الرمز الموقّع يُتحقَّق منه في كل طلب كما كان، وعمره خمس عشرة دقيقة كما
// كان. والمركز يعيد في كل تجديد فحصَ الحساب والوصول والمنصة ومفتاح
// الإبطال — فالموقوف مركزياً يخرج خلال ربع ساعة كما كان، ولو ضاع إشعار
// الخروج الخلفي. والذي تغيّر أن الجلسة صار يحكمها عمرُ جلسة المركز التي
// أصدرت رمز التجديد، لا عمرُ الرمز الواحد.

import { AuthError, sessionKeyFor, userIndexKeyFor } from './safe.js';
import { verifyToken } from './verify.js';

/** مهلة النداء إلى المركز — السبب في `callback.js`. */
const CENTER_TIMEOUT_MS = 5000;

/**
 * عمر كوكي «تذكّرني» في المتصفح: أقصى ما يقبله كروم (٤٠٠ يوم).
 *
 * الحدّ الحقيقي في `KV` لا هنا — الكوكي يحمل المعرّف والسجلّ يقرّر. ولا
 * يُعاد إصدار الكوكي مع كل تجديد (الوسيط لا يكتب في الاستجابة)، فلو كان
 * عمره عمرَ السجلّ لانتهى في المتصفح والسجلّ ممدودٌ حيّ.
 */
const REMEMBER_COOKIE_SECONDS = 400 * 86400;

/** `KV` لا يقبل عمراً دون ستين ثانية. */
const kvTtl = (seconds) => Math.max(60, Math.floor(seconds));

/**
 * عمر الجلسة في `KV` وعمر كوكيّها.
 *
 * - مع رمز تجديد: عمرُ جلسة المركز المتبقي كما ردّه، وكوكيٌّ طويل مع
 *   «تذكّرني» أو كوكيُّ جلسةِ تصفّح (`null`) بدونه — يُمحى بإغلاق
 *   المتصفح كما يُمحى كوكيّ المركز.
 * - بلا رمز تجديد (مركزٌ لم يُحدَّث بعد): ما بقي من عمر الرمز، كما كان.
 */
export function sessionLifetime({ exp, refresh, refreshExpiresIn, remember }) {
  if (refresh && Number.isFinite(refreshExpiresIn) && refreshExpiresIn > 60) {
    return {
      ttl: kvTtl(refreshExpiresIn),
      cookieMaxAge: remember ? REMEMBER_COOKIE_SECONDS : null,
    };
  }
  const ttl = kvTtl(exp - Math.floor(Date.now() / 1000));
  return { ttl, cookieMaxAge: ttl };
}

/**
 * يجدّد رمز الجلسة من المركز ويكتبها من جديد.
 *
 * يعيد واحداً من ثلاثة:
 * - `{ claims }`       رمزٌ جديد تحقّقنا منه، والجلسة مكتوبة به.
 * - `{ ended: true }`  المركز رفض: انتهت جلسته أو أُوقف الحساب أو سُحب
 *                      الوصول. على المتّصل محو الجلسة والعودة إلى المركز.
 * - `{ unavailable: true }`  تعذّر السؤال الآن. الجلسة باقية، والطلب يُردّ
 *                      ٥٠٣ — الحكم على الشبكة لا على صاحبها.
 */
export async function refreshSession(env, config, sid, session) {
  const secret = env[config.secretBinding];
  if (!secret) {
    if (config.onError) config.onError('secret_missing', new AuthError('secret_missing'));
    return { unavailable: true };
  }

  let res;
  try {
    res = await fetch(`${config.issuer}/api/refresh`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ platformId: config.platformId, secret, refresh: session.refresh }),
      signal: AbortSignal.timeout(CENTER_TIMEOUT_MS),
    });
  } catch (err) {
    if (config.onError) config.onError('refresh_unreachable', err);
    return { unavailable: true };
  }

  /* ٤٠٠ و٤٠٣ حكمٌ على صاحب الجلسة: رمز تجديدٍ سقط مع جلسة المركز، أو
     حسابٌ أُوقف، أو وصولٌ سُحب. وما عداهما — سرٌّ رُفض، حدُّ معدّل، عطلٌ
     في المركز — حكمٌ على المنصة أو الشبكة، فلا يُعاقَب به العضو. */
  if (res.status === 400 || res.status === 403) {
    if (config.onError) config.onError('refresh_rejected', new AuthError('refresh_rejected'));
    return { ended: true };
  }
  if (!res.ok) {
    if (config.onError) {
      config.onError('refresh_failed', new AuthError('refresh_failed', `المركز ردّ ${res.status}`));
    }
    return { unavailable: true };
  }

  const body = await res.json().catch(() => null);
  if (!body || typeof body.token !== 'string' || !body.token) {
    if (config.onError) config.onError('refresh_malformed', new AuthError('refresh_malformed'));
    return { unavailable: true };
  }

  let claims;
  try {
    claims = await verifyToken(body.token, env, config);
  } catch (err) {
    if (config.onError) config.onError('refresh_verify_failed', err);
    return { unavailable: true };
  }

  // صاحبُ الرمز الجديد صاحبُ الجلسة نفسه — وإلا فشيءٌ اختلط في المركز.
  if (claims.sub !== session.sub) return { ended: true };

  const { ttl } = sessionLifetime({
    exp: claims.exp,
    refresh: session.refresh,
    refreshExpiresIn: Number(body.refreshExpiresIn),
    remember: body.remember === true,
  });

  const kv = config.kv(env);
  await kv.put(
    await sessionKeyFor(sid),
    JSON.stringify({ ...session, token: body.token, exp: claims.exp, remember: body.remember === true }),
    { expirationTtl: ttl },
  );
  // والدليل من العضو إلى جلساته يُمدّ معها، وإلا سقط قبلها فلا يجدها
  // إشعار الخروج الخلفي.
  await kv.put(await userIndexKeyFor(session.sub, sid), '1', { expirationTtl: ttl });

  return { claims };
}
