// تعريفات الأنواع — المنصات مكتوبة بـ TypeScript، فبلا هذا الملف يفشل
// بناء كل واحدة منها عند أول استيراد. مكتوبة يدوياً لأن الحزمة JavaScript
// خالص بلا خطوة بناء، وإضافة مترجم هنا تبعية على المنصات الخمس.

export interface MemberSchema {
  table: string;
  id: string;
  name: string;
  email: string;
  role: string;
  perms: string | null;
  isActive: string;
  lastSeenAt: string | null;
  createdAt: string;
}

/** محتوى الرمز بعد التحقق. الأربعة الأولى مضمونة — `verifyToken` يرفض بدونها. */
export interface Claims {
  sub: string;
  iss: string;
  aud: string;
  exp: number;
  name?: string;
  email?: string;
  iat?: number;
  [key: string]: unknown;
}

export interface Member {
  id: string;
  role: string;
  perms: Record<string, unknown> | null;
  isActive: boolean;
}

export interface AuthConfig {
  issuer: string;
  platformId: string;
  secretBinding: string;
  dbBinding: string;
  kvBinding: string;
  kv: (env: any) => any;
  schema: MemberSchema;
  defaultRole: string;
  timeFormat: 'epoch' | 'iso';
  cookieName: string;
  deniedPath: string;
  publicPaths: string[];
  publicPrefixes: string[];
  apiPrefixes: string[];
  reasons: Record<string, string>;
  onError: ((code: string, error: unknown) => void) | null;
  onClaims: ((claims: Claims, env: any, config: AuthConfig) => unknown) | null;
}

export interface AuthConfigOverrides extends Partial<Omit<AuthConfig, 'schema'>> {
  schema?: Partial<MemberSchema>;
}

export function createConfig(env: any, overrides?: AuthConfigOverrides): AuthConfig;

/** إمّا استجابة جاهزة (تحويل أو رفض)، وإمّا مستخدم، وإمّا مسار عام. */
export interface AuthResult {
  response?: Response;
  user?: { id: string; role: string; perms: Record<string, unknown> | null };
  /** محتوى الرمز بعد التحقق منه في هذا الطلب — لا يُفكّ في المنصة بلا تحقّق. */
  claims?: Claims;
  session?: { sub: string; token: string; exp: number };
  public?: boolean;
}

export function authenticate(request: Request, env: any, config: AuthConfig): Promise<AuthResult>;
export function startLogin(request: Request, env: any, config: AuthConfig): Promise<Response>;
export function isPublicPath(pathname: string, config: AuthConfig): boolean;
export function deniedResponse(request: Request, config: AuthConfig, reason: string): Response;

/** هل الطلب تنقّلٌ يعرض صفحة؟ `Sec-Fetch-Mode` ثم `Accept` ثم `apiPrefixes`. */
export function wantsDocument(request: Request, url: URL, config: AuthConfig): boolean;
export function pagesMiddleware(config: AuthConfig): (context: any) => Promise<Response>;
export function honoMiddleware(config: AuthConfig): (c: any, next: () => Promise<void>) => Promise<Response | void>;

export function handleCallback(request: Request, env: any, config: AuthConfig): Promise<Response>;
export function pagesCallback(config: AuthConfig): (context: any) => Promise<Response>;
export function reportAccessChange(
  env: any,
  config: AuthConfig,
  change: { email: string; state: 'granted' | 'revoked'; reason?: string },
): Promise<boolean>;

export function verifyToken(token: string, env: any, config: AuthConfig): Promise<Claims>;

export function getMember(env: any, config: AuthConfig, userId: string): Promise<Member | null>;
export function upsertMember(env: any, config: AuthConfig, claims: Claims): Promise<Member | null>;
export function touchMember(env: any, config: AuthConfig, userId: string): Promise<void>;

export function safeNext(next: unknown): string;
export function randomToken(bytes?: number): string;
export function newSessionId(): string;
export function normaliseIssuer(issuer: string): string;
export function sessionCookie(name: string, value: string, maxAgeSeconds: number): string;
export function clearCookie(name: string): string;
export function readCookie(request: Request, name: string): string | null;
export function timingSafeEqual(a: string, b: string): boolean;

export class AuthError extends Error {
  constructor(code: string, message?: string);
  code: string;
}

export const DEFAULT_SCHEMA: MemberSchema;
export const DEFAULT_API_PREFIXES: string[];
export const DEFAULT_PUBLIC_PATHS: string[];
export const DEFAULT_PUBLIC_PREFIXES: string[];
export const DEFAULT_REASONS: Record<string, string>;
export const JWKS_TTL_SECONDS: number;
export const CLOCK_SKEW_SECONDS: number;
