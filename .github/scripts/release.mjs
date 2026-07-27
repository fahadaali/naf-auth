/**
 * يقرّر رقم الإصدار التالي من أوصاف الالتزامات، ويكتب CHANGELOG.md.
 *
 * لا يلمس Git ولا GitHub — يقرأ ويكتب ملفاً واحداً ويطبع النتيجة.
 * التوسيم والنشر مسؤولية سير العمل، ليبقى هذا الملف قابلاً
 * للتشغيل محلياً بلا صلاحيات.
 *
 * قواعد الاستنتاج:
 *   feat!  أو  BREAKING CHANGE:  ->  رئيسي
 *   feat                         ->  ثانوي
 *   fix                          ->  إصلاحي
 *   ما عداه                      ->  لا شيء
 *
 * المخرج على stdout بصيغة key=value لسير العمل:
 *   release=true|false
 *   version=1.2.0
 *   tag=v1.2.0
 *   bump=major|minor|patch|none
 */

import { execFileSync } from "node:child_process"
import { existsSync, readFileSync, writeFileSync } from "node:fs"

const CHANGELOG = "CHANGELOG.md"

// فاصلان لا يظهران في نص عادي، فلا ينكسر التحليل على وصف متعدد الأسطر
const FIELD = ""
const RECORD = ""

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim()
}

/** آخر وسم إصدار، أو null لو لم يوجد وسم بعد */
function lastTag() {
  try {
    return git("describe", "--tags", "--abbrev=0", "--match", "v*")
  } catch {
    return null
  }
}

function commitsSince(tag) {
  const range = tag ? `${tag}..HEAD` : "HEAD"
  const raw = git("log", range, `--format=%H${FIELD}%s${FIELD}%b${RECORD}`)
  return raw
    .split(RECORD)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [hash, subject, body = ""] = entry.split(FIELD)
      return { hash, subject, body }
    })
}

const HEADER = /^(?<type>[a-z]+)(?<scope>\([^)]*\))?(?<bang>!)?:\s*(?<summary>.+)$/

function classify(commit) {
  const match = HEADER.exec(commit.subject)
  if (!match) return null

  const { type, scope, bang, summary } = match.groups
  const breaking = Boolean(bang) || /^BREAKING CHANGE:/m.test(commit.body)

  return {
    type,
    scope: scope ? scope.slice(1, -1) : null,
    summary,
    breaking,
    hash: commit.hash,
  }
}

function decideBump(entries) {
  if (entries.some((entry) => entry.breaking)) return "major"
  if (entries.some((entry) => entry.type === "feat")) return "minor"
  if (entries.some((entry) => entry.type === "fix")) return "patch"
  return "none"
}

function nextVersion(tag, bump) {
  const [major, minor, patch] = (tag ?? "v0.0.0").replace(/^v/, "").split(".").map(Number)
  if (bump === "major") return `${major + 1}.0.0`
  if (bump === "minor") return `${major}.${minor + 1}.0`
  return `${major}.${minor}.${patch + 1}`
}

const SECTIONS = [
  { title: "تغييرات كاسرة", pick: (entry) => entry.breaking },
  { title: "ميزات", pick: (entry) => entry.type === "feat" && !entry.breaking },
  { title: "إصلاحات", pick: (entry) => entry.type === "fix" && !entry.breaking },
]

function renderSection(version, date, entries) {
  const lines = [`## ${version} — ${date}`, ""]

  for (const section of SECTIONS) {
    const picked = entries.filter(section.pick)
    if (picked.length === 0) continue

    lines.push(`### ${section.title}`, "")
    for (const entry of picked) {
      const scope = entry.scope ? `**${entry.scope}:** ` : ""
      lines.push(`- ${scope}${entry.summary} (\`${entry.hash.slice(0, 7)}\`)`)
    }
    lines.push("")
  }

  return lines.join("\n")
}

function prependChangelog(section) {
  const title = "# سجلّ التغييرات\n\nيُولَّد آلياً من أوصاف الالتزامات. لا يُحرَّر يدوياً.\n"
  const existing = existsSync(CHANGELOG) ? readFileSync(CHANGELOG, "utf8") : ""
  const body = existing.startsWith("#") ? existing.split("\n").slice(3).join("\n").trim() : existing.trim()

  writeFileSync(CHANGELOG, `${title}\n${section}\n${body ? `${body}\n` : ""}`, "utf8")
}

function emit(values) {
  for (const [key, value] of Object.entries(values)) {
    console.log(`${key}=${value}`)
  }
}

// ── التنفيذ ───────────────────────────────────────────────────

const tag = lastTag()
const entries = commitsSince(tag).map(classify).filter(Boolean)
const bump = decideBump(entries)

if (bump === "none") {
  emit({ release: "false", bump: "none" })
  process.exit(0)
}

const version = nextVersion(tag, bump)
const date = git("log", "-1", "--format=%cs")
const section = renderSection(version, date, entries)

prependChangelog(section)
writeFileSync("release-notes.md", section, "utf8")

emit({ release: "true", bump, version, tag: `v${version}` })
