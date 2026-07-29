// naf-auth — التحقق من الرمز الموقّع
// عبر WebCrypto مباشرة، وبلا أي اتصال بقاعدة المركز.

import { AuthError, base64UrlToBytes, base64UrlToText, normaliseIssuer } from './safe.js';

/**
 * كاش المفاتيح العامة: خمس دقائق — وهي المدّة التي يقرّرها المركز في عقده.
 *
 * وهي سقفُ ما يتأخّره التدوير: المركز ينشر المفتاح التالي، ثم ينتظر أن
 * تكون كل منصة قد قرأت `JWKS` قبل أن ينقله ليوقّع. فمنصةٌ تخبّئ ساعةً
 * تُخلّ بهذا الانتظار وترفض الرموز الجديدة حتى ينقضي كاشها.
 */
const JWKS_TTL_SECONDS = 300;

/** فارق الساعة المسموح: ٦٠ ثانية (الاحتراز الرابع في §١٠). */
const CLOCK_SKEW_SECONDS = 60;

/** الخوارزمية الوحيدة المقبولة. أي قيمة أخرى ترفض قبل أي عمل تعمية. */
const ALG = 'RS256';

/**
 * مهلة جلب `JWKS`.
 *
 * بلا مهلة يرث الطلبُ مهلةَ المنصة كلها: مركزٌ يقبل الاتصال ولا يردّ يُعلّق
 * كل طلب محميّ حتى ينفد وقت الـWorker، فيصل صاحبَه خطأ منصّة لا خطأ دخول.
 * والمركز نفسه يضع ثلاث ثوانٍ على نداء الخروج الخلفي — وهذه الجهة أولى بها،
 * فهي في المسار الحرج لكل طلب لا في إشعارٍ لاحق.
 */
const JWKS_TIMEOUT_MS = 3000;

/**
 * مهلة بين إجبارَي جلبٍ متتاليين عند `kid` مجهول.
 *
 * ستون ثانية: أقلُّ ما يقبله `KV` عمراً، وهو كافٍ — التدوير حدثٌ واحد لا
 * سيل، فأوّلُ طلبٍ بعده يجلب المفتاح الجديد ويخبّئه لمن يليه.
 */
const FORCE_COOLDOWN_SECONDS = 60;

/**
 * أخطاء الرمز نفسه — يقابلها أخطاءُ عجزِ المتحقّق (`jwks_unavailable`
 * و`jwks_malformed` وما ليس `AuthError` أصلاً).
 *
 * والفرق ليس تصنيفاً: الوسيط يمحو الجلسة على الأولى ولا يمحوها على الثانية.
 * «الرمز باطل» حكمٌ على الرمز، و«عجزتُ عن الفحص» حكمٌ على الشبكة — ومحوُ
 * جلسةٍ صحيحة لأن المركز تعثّر لحظةً يُخرج أعضاءً لم يُخطئوا شيئاً.
 */
export const TOKEN_ERRORS = new Set([
  'token_malformed',
  'bad_alg',
  'missing_kid',
  'unknown_kid',
  'bad_signature',
  'bad_issuer',
  'bad_audience',
  'missing_exp',
  'token_expired',
  'token_not_yet_valid',
  'token_from_future',
  'missing_sub',
  'wrong_token_type',
]);

/** هل هذا خطأُ رمزٍ باطل، أم عجزٌ عن التحقق؟ */
export function isTokenError(err) {
  return err instanceof AuthError && TOKEN_ERRORS.has(err.code);
}

function jwksUrl(issuer) {
  return `${normaliseIssuer(issuer)}/.well-known/jwks.json`;
}

/**
 * جلب المفاتيح العامة مع الكاش.
 * `force` يتجاوز الكاش — يُستعمل عند مقابلة `kid` غير معروف.
 */
async function loadJwks(env, config, force = false) {
  const kv = config.kv(env);
  const cacheKey = `jwks:${config.issuer}`;

  if (!force) {
    const cached = await kv.get(cacheKey, 'json');
    if (cached && Array.isArray(cached.keys)) return cached;
  }

  let res;
  try {
    res = await fetch(jwksUrl(config.issuer), {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(JWKS_TIMEOUT_MS),
    });
  } catch {
    // انقطاعُ شبكةٍ أو نفادُ مهلة — عجزٌ عن التحقق لا رمزٌ باطل.
    throw new AuthError('jwks_unavailable');
  }
  if (!res.ok) throw new AuthError('jwks_unavailable');

  let jwks;
  try {
    jwks = await res.json();
  } catch {
    throw new AuthError('jwks_malformed');
  }
  if (!jwks || !Array.isArray(jwks.keys)) throw new AuthError('jwks_malformed');

  /* تعذّرُ الكتابة لا يُسقط تحقّقاً نجح.
     المخبأ تسريعٌ لا شرط: الكتابة على مفتاح واحد ساخن قد تُردّ بحدّ معدّل
     في KV، ورميُها من هنا يُبطل رمزاً سليماً بيد صاحبه — ويمحو جلسته. */
  try {
    await kv.put(cacheKey, JSON.stringify(jwks), { expirationTtl: JWKS_TTL_SECONDS });
  } catch {
    /* يمضي بلا مخبأ: الطلب التالي يجلب من جديد. */
  }
  return jwks;
}

function findKey(jwks, kid) {
  // المركز قد ينشر مفتاحين معاً للتدوير، فالاختيار بـ kid لا بالأول.
  return jwks.keys.find((k) => k.kid === kid && (k.kty === 'RSA') && (!k.alg || k.alg === ALG)) || null;
}

async function importKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: ALG, ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
}

function decodeJwt(token) {
  if (typeof token !== 'string') throw new AuthError('token_malformed');
  const parts = token.split('.');
  if (parts.length !== 3) throw new AuthError('token_malformed');

  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlToText(parts[0]));
    payload = JSON.parse(base64UrlToText(parts[1]));
  } catch {
    throw new AuthError('token_malformed');
  }

  return {
    header,
    payload,
    signature: base64UrlToBytes(parts[2]),
    signingInput: new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  };
}

/**
 * `aud` مقارنةٌ حرفية بمعرّف المنصة — نصّاً لا مصفوفة.
 *
 * المركز يوقّع `aud` نصّاً واحداً دائماً، فقبول المصفوفة توسيعٌ لا يقابله
 * شيء في العقد. والمعرّف حسّاس لحالة الأحرف ولا يُطبَّع: منصةٌ تخفض
 * `NAF-Accountant` إلى حروف صغيرة ترفض كل رمز صحيح، ورفضاً صامتاً.
 */
function audienceMatches(aud, platformId) {
  return typeof aud === 'string' && aud === platformId;
}

/**
 * نوع الرمز — الفرق الوحيد بين رمز الدخول ورمز إشعار الخروج الخلفي.
 *
 * كلاهما من المركز، بالمفتاح نفسه و`iss` نفسه و`aud` معرّفِ هذه المنصة،
 * فكلاهما يجتاز التوقيع والمُصدِر والجمهور والمدّة. ولولا هذا التمييز لصلح
 * إشعارُ الخروج — وهو يصل إلى مسار عامّ لا حراسة عليه — أن يُقدَّم كرمز
 * جلسة. فيُشترط الغرض في الجهتين: مفقوداً في رمز الدخول، وموجوداً في الإشعار.
 *
 * واسمه `purpose` لا `typ`: ترويسة JOSE فيها `typ` أصلاً بقيمة `JWT`،
 * فحقلٌ ثانٍ بالاسم نفسه في الحمولة يجعل قارئ الرمز يظنّ أحدهما الآخر.
 */
export const LOGOUT_PURPOSE = 'backchannel-logout';

/**
 * التحقق الكامل (الاحتراز الرابع في §١٠): التوقيع و `iss` و `aud` و `exp` معاً.
 * رمز منصة أخرى يُرفض بـ `aud`، والمنتهي يُرفض بـ `exp`.
 *
 * و`expectedPurpose` يُفحص على الحمولة الموقَّعة نفسها — لا على نسخةٍ منها
 * تُعاد صياغتها. الرمز يُتحقّق منه كما وصل حرفاً بحرف: التوقيع يغطّي نصَّ
 * الحمولة، فأيّ إعادة ترميزٍ لها تُبطله.
 */
async function verifySigned(token, env, config, expectedPurpose) {
  const { header, payload, signature, signingInput } = decodeJwt(token);

  // يُفحص قبل أي شيء: `none` و`HS256` بمفتاح عام هجومان معروفان على هذا الموضع.
  if (header.alg !== ALG) throw new AuthError('bad_alg');
  if (!header.kid) throw new AuthError('missing_kid');

  let jwks = await loadJwks(env, config);
  let jwk = findKey(jwks, header.kid);

  /* الاحتراز الخامس في §١٠: معرّف مفتاح غير معروف يعيد الجلب فوراً، وإلا
     تعطّلت المنصة عند كل تدوير مفاتيح حتى ينقضي المخبأ.

     ═══ لكنّ إعادة الجلب لا تُترك بلا سقف ═══

     `‎/auth/backchannel-logout` مسارٌ عامّ بلا مصادقة — وهو كذلك بالضرورة،
     فالمنادي خادمُ المركز لا متصفّح. ورمزٌ مركَّب بـ`kid` عشوائي يجتاز
     فحصَي `alg` و`kid` ويبلغ هذا السطر **قبل التحقق من التوقيع**: فحصُ
     التوقيع يحتاج المفتاح، والمفتاح هو ما يُجلب. فكلُّ طلبٍ مزوَّر كان
     يُجبر جلباً شبكياً إلى المركز وكتابةً في `KV` — بلا حدّ، ومن أي أحد.
     فتصير المنصةُ مضخِّمَ حِملٍ على مركزها.

     فيُقيَّد الإجبار بمهلةٍ قصيرة: أوّلُ `kid` مجهول يجلب، وما يليه خلال
     المهلة يُردّ بلا شبكة. والتدوير لا يتأثّر — هو حدثٌ واحد لا سيلٌ،
     وأوّلُ طلبٍ بعده يجلب المفتاح الجديد ويخبّئه للبقية. */
  if (!jwk) {
    const cooldownKey = `jwksforce:${config.issuer}`;
    const kv = config.kv(env);
    const cooling = await kv.get(cooldownKey);

    if (!cooling) {
      try {
        await kv.put(cooldownKey, '1', { expirationTtl: FORCE_COOLDOWN_SECONDS });
      } catch {
        /* تعذّرُ كتابة المهلة لا يمنع الجلب — الحدّ تحسينٌ لا شرط. */
      }
      jwks = await loadJwks(env, config, true);
      jwk = findKey(jwks, header.kid);
    }
  }
  if (!jwk) throw new AuthError('unknown_kid');

  const key = await importKey(jwk);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signingInput);
  if (!valid) throw new AuthError('bad_signature');

  // مقارنةٌ حرفية. و`config.issuer` وُحّدت صورتُه مرة واحدة عند بناء
  // الإعداد، فما يُقارَن هنا هو `iss` كما وقّعه المركز بلا تطبيع.
  if (payload.iss !== config.issuer) throw new AuthError('bad_issuer');
  if (!audienceMatches(payload.aud, config.platformId)) throw new AuthError('bad_audience');

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number') throw new AuthError('missing_exp');
  if (now > payload.exp + CLOCK_SKEW_SECONDS) throw new AuthError('token_expired');
  if (typeof payload.nbf === 'number' && payload.nbf > now + CLOCK_SKEW_SECONDS) {
    throw new AuthError('token_not_yet_valid');
  }
  if (typeof payload.iat === 'number' && payload.iat > now + CLOCK_SKEW_SECONDS) {
    throw new AuthError('token_from_future');
  }

  if (!payload.sub || typeof payload.sub !== 'string') throw new AuthError('missing_sub');

  // الغرض آخِرَ ما يُفحص لأنه أرخص ما يُفحص، ولا يُقبل ضمناً في الحالين:
  // رمزُ جلسةٍ يُشترط ألّا يحمله، ورمزُ خروجٍ يُشترط أن يحمله.
  if ((payload.purpose ?? null) !== expectedPurpose) throw new AuthError('wrong_token_type');

  return payload;
}

/** رمز الدخول — ولا يحمل غرضاً. */
export function verifyToken(token, env, config) {
  return verifySigned(token, env, config, null);
}

/** رمز إشعار الخروج الخلفي — ولا يصلح جلسةً. */
export function verifyLogoutToken(token, env, config) {
  return verifySigned(token, env, config, LOGOUT_PURPOSE);
}

export { JWKS_TTL_SECONDS, CLOCK_SKEW_SECONDS };
