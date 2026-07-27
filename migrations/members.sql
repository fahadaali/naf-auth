-- naf-auth — جدول الأعضاء المحلي. يُنسخ في كل منصة (§٥).
--
-- هذا مخطّط منصة جديدة بلا مستخدمين سابقين.
-- منصة لها نظام أعضاء قائم لا تنشئ هذا الجدول: تُرحَّل هويتها إلى `sub`
-- القادم من المركز بخطة ترحيل مستقلة، ثم تُضبط أسماء جدولها وأعمدتها
-- في `wrangler.toml` كما في `README`. الهجرات للأمام فقط (§١٠).

CREATE TABLE IF NOT EXISTS members (
  user_id      TEXT PRIMARY KEY,   -- sub القادم من المركز
  display_name TEXT,
  email        TEXT,
  role         TEXT NOT NULL DEFAULT 'viewer',   -- admin | editor | viewer
  perms        TEXT,               -- JSON للصلاحيات الدقيقة
  is_active    INTEGER NOT NULL DEFAULT 1,
  last_seen_at INTEGER,
  created_at   INTEGER NOT NULL
);

-- البحث بالبريد عند مطابقة عضو قادم بسجلّ قائم.
CREATE INDEX IF NOT EXISTS idx_members_email ON members(email);

-- ملاحظة على الدور: لا قيد CHECK على `role` عمداً.
-- المصادقة مركزية والصلاحيات موزّعة (§١)، فمفردات الأدوار تخصّ كل منصة،
-- وقيدٌ هنا يمنع منصة من استعمال أدوارها هي.
