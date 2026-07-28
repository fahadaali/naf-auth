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

  const res = await fetch(jwksUrl(config.issuer), {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new AuthError('jwks_unavailable');

  const jwks = await res.json();
  if (!jwks || !Array.isArray(jwks.keys)) throw new AuthError('jwks_malformed');

  await kv.put(cacheKey, JSON.stringify(jwks), { expirationTtl: JWKS_TTL_SECONDS });
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

  // الاحتراز الخامس في §١٠: معرّف مفتاح غير معروف يعيد الجلب فوراً،
  // وإلا تعطّلت المنصة ساعة كاملة عند كل تدوير مفاتيح.
  if (!jwk) {
    jwks = await loadJwks(env, config, true);
    jwk = findKey(jwks, header.kid);
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
