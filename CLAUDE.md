# NAF UI Rules

Place at the root of every NAF repository — the five platforms and `naf-ui` itself.
These are constraints, not suggestions. Five codebases drifted apart; this file is what stops it happening again.

Registry address: `fahadaali/naf-ui`
Pin to a release: `fahadaali/naf-ui/button#v1.0.0`

---

## 0. The governing principle

**The registry precedes the platform.**

Every design decision — a colour, a term, an icon meaning, a component — is recorded in `naf-ui` *before* it is applied anywhere else. A decision applied in a platform without being registered is drift, even when the decision itself is correct.

This is what makes the work shrink instead of repeat. The first platform surfaces twenty decisions; by the fifth, nearly all of them are already settled.

When you find yourself about to decide something locally: stop, register it, then apply it.

---

## 1. The one rule

**Never write a raw design value.** No hex codes, no `rgb()`, no arbitrary pixel spacing, no font stacks, no ad-hoc radii, no inline shadows.

```jsx
// rejected
<div style={{ background: '#1B4B5A', padding: '13px' }}>
<div className="bg-[#1B4B5A] p-[13px] text-[15px]">

// correct
<div className="bg-primary p-4 rounded-md">
```

If a value you need does not exist in the token set, **stop and ask**. Adding a token is a deliberate decision made once in `naf-ui`, never per-component.

**No parallel systems.** A platform must not define its own theme, token set, colour scale or utility palette in `tailwind.config.js` or anywhere else. If you find one, it predates this system and must be replaced entirely and its definition removed. Two sources of truth in one repository is worse than no system at all.

**Four exceptions, and only these four.** Every one of them is a context that cannot read a CSS custom property. Nothing else qualifies — "it was simpler" is not a context.

*Email templates.* Email clients do not support CSS custom properties, and older desktop clients do not support logical direction properties either. A template that renders inside an inbox carries literal values and physical direction properties by necessity, and so does any in-app preview of it — a preview styled from the app theme shows the author something the subscriber will never receive. Keep those values in one template file, comment why, and mirror the same values in the preview. In an RTL template that means `border-right` where the app would use `border-inline-start`; write the RTL side directly and say so in a comment. Everything else in the same repository still obeys the rule.

*External brand colours.* Platform marks — LinkedIn, X, Instagram, YouTube, Facebook, TikTok, Snapchat, Threads, Google — are identities owned by other parties. Recolouring them to fit our theme makes them unrecognisable, which defeats the icon. They are registered as `--brand-*` tokens in `naf-theme.css`; consume those. Never type the hex, and never use a `--brand-*` token for anything but that platform's own mark.

*Print and PDF documents.* A document generated into its own window — `document.write`, a print stylesheet, a server-rendered PDF — does not inherit the app's stylesheet and cannot resolve `var(--…)`. It also must stay light regardless of the reader's theme: a dark-themed invoice wastes toner and a dark-themed pleading is not filed. Keep those values in the one function that builds the document, comment why, and never let them leak back into the interface. Substituting tokens there does not degrade the output — it breaks the export.

*`<meta name="theme-color">`.* The tag takes a literal colour and nothing else; no browser resolves `var()` inside it. Mirror `--background` for both modes and update the two literals whenever the theme changes. This is the only place in an app shell where a background colour is written by hand.

---

## 2. RTL is the default

All five platforms serve Arabic first. Physical direction properties will break every layout.

| Never | Always |
|---|---|
| `ml-*` `mr-*` | `ms-*` `me-*` |
| `pl-*` `pr-*` | `ps-*` `pe-*` |
| `left-*` `right-*` | `start-*` `end-*` |
| `text-left` `text-right` | `text-start` `text-end` |
| `border-l` `border-r` | `border-s` `border-e` |
| `rounded-l-*` `rounded-r-*` | `rounded-s-*` `rounded-e-*` |
| `float-left` `float-right` | `float-start` `float-end` |

In plain CSS use `margin-inline-start`, `padding-inline-end`, `inset-inline-start`, `border-inline-start`.

**Mixed-direction content.** Any string mixing Arabic with digits, Latin words, phone numbers, IBANs, currency, dates, case numbers or filenames must be isolated, or Arabic reorders it:

```jsx
<span>المبلغ <bdi>12,400.00</bdi> ريال</span>
<span>الملف <bdi>report.pdf</bdi> جاهز</span>
<span>قضية رقم <bdi>2291/ت/1447</bdi></span>
```

Case numbers and reference numbers containing slashes are the highest-risk case. Verify them visually in the browser, not only in code.

---

## 3. Icons

**Library: Lucide, exclusively.** Never import an icon from any other library. Never inline an SVG that duplicates an existing Lucide icon.

**Emoji are banned in user interfaces, without exception.** Not as icons, not as decoration, not in buttons, labels, empty states or alerts.

The reasons are technical, not aesthetic:
- They render differently on every operating system — the client sees a different interface than you do
- They do not inherit text colour or weight, so they escape the theme in both modes
- Screen readers announce them by unintended names
- Directional emoji do not mirror in RTL

**One exception, and it is narrow: third-party messaging surfaces.** Telegram, WhatsApp, SMS, Basecamp message boards and email bodies cannot render an SVG inline, so Lucide is not available there and the ban would leave those messages with no visual structure at all. Emoji are permitted in message bodies sent through such a channel — and nowhere else. Not in the web interface, not in a page the platform itself renders, not in a PDF it generates.

The technical reasons for the ban still hold on those surfaces; they are simply unavoidable there. So keep the set small and conventional, never carry meaning by emoji alone, and make sure the sentence reads correctly with every emoji stripped out. A message that becomes ambiguous without its icons is written wrong.

**Meaning comes from `naf-icons.md`.** One meaning, one icon, across all five platforms. Never pick an icon for a concept already mapped there.

When you meet an emoji or a concept whose meaning is not in the map: do not invent a match, and do not use the nearest icon by shape. Show the surrounding context, ask for the decision, then add the approved mapping to `naf-icons.md` in the registry **before** applying it.

**Mirroring.** Mirror: arrows, chevrons, back, forward, send, reply, indent.
Do not mirror: logos, brand marks, clocks, checkmarks, search, user, media play, photographs.

**Version pinning.** `lucide-react` is pinned to an exact version — no `^`, no `~` — in two places: `package.json` and `registry.json`. Lucide renames icons between major versions, keeps the old name as a deprecated alias, then removes it. An open range means an icon disappears at build time with no warning.

The version appears in two files. Changing one without the other makes the preview page show one version while platforms run another, which destroys the preview's value as a reference.

**Major upgrades are a four-step procedure, never a single-repo change:**
1. Run `/verify-icons` on all six repositories before raising any number
2. Review the reported missing and deprecated names with their proposed replacements
3. Approve the table, apply in `naf-ui` first, then the platforms
4. Raise the pin in all six together

Never upgrade in one repository alone. Six repositories on two different icon vocabularies is precisely the drift this file exists to prevent.

---

## 4. Components

- **Never rebuild what exists in the registry.** Check `naf-ui` first, every time.
- A new shared component is a decision. If a screen needs something new, ask before adding it.
- Components accept `className` and forward refs. They never hardcode outer margins — spacing belongs to the parent.
- Every interactive element needs a visible `:focus-visible` state. Do not remove it with `outline-none` without an equally visible replacement.
- Three control heights only: `sm`, `md`, `lg`. `md` is the default. No other height exists.

---

## 5. Typography

- One family. Never import another font anywhere.
- Weights 400, 500, 600, 700 only.
- Sizes from the scale. Never `text-[15px]`. The scale is registered as `--text-xs` through `--text-5xl` in `naf-theme.css`, so a platform writing plain CSS consumes the same steps as a platform writing Tailwind. Setting a size by hand is how seventeen sizes appear in one stylesheet.
- **Do not reduce line heights.** The scale is deliberately taller than a Latin-only scale because Arabic needs vertical room for ascenders, descenders and diacritics.
- Long-form body copy gets a capped measure.

---

## 6. Colour

Semantic tokens for interface, palette steps for decoration only:

```
bg-background  bg-card  bg-muted
text-foreground  text-muted-foreground
border-border
bg-primary  text-primary-foreground  hover:bg-primary/90
```

- Accent is emphasis, not decoration. More than one accent element visible at once means one is wrong.
- Never communicate meaning by colour alone — pair status colours with an icon and a label.
- Light and dark must both work. Test both.

**Our own mark.** The navy, mint and taupe of the NAF mark are registered as `--mark-navy`, `--mark-mint` and `--mark-taupe`, taken from the logo files themselves rather than sampled by eye. They exist to render the mark and nothing else. An interface element takes a semantic token — a heading is `text-foreground`, never `text-mark-navy`, however well the navy happens to suit it. The rule is the same one that governs `--brand-*`: an identity colour is not a palette.

**Status text on soft backgrounds.** A status colour token on its own `--*-soft` background reaches only 3.7–3.8:1 — below AA for badge-sized text. Use `--success-strong`, `--warning-strong`, `--destructive-strong`, `--info-strong` and `--primary-strong` for the text and icon in that pairing; they are the same hue at a lightness measured to clear 4.5:1 in both modes. Never darken a status colour by hand to fix contrast.

**The deep surface.** `--surface-deep` is the semantic dark surface — page backgrounds outside the card, slide covers, section dividers — with `--surface-deep-foreground` for text on it and `--surface-deep-muted` for secondary text. It is not `--mark-navy`: that renders the mark and nothing else. A dark surface takes the semantic token even when the mark's navy would look identical.

**Elevated cards.** A card floating on `--surface-deep` needs more depth than the ordinary shadow scale carries. Use `--shadow-elevated`; do not write an `rgba` shadow to get there.

**Soft state backgrounds.** `--primary-soft`, `--destructive-soft`, `--success-soft`, `--warning-soft`, `--info-soft` and `--secondary-soft` are derived from their base token by `color-mix` into the card surface, so they follow both modes from a single definition. Use them for status badges and quiet alerts. Never define your own soft value — a hand-picked tint is the exact drift that survives a palette change and then clashes with it.

**Appearance follows the reader, and the reader may override it.** Both modes must work, and a platform that offers a switch uses the registered one: three states — system, light, dark — with system as the default, the choice persisted, and `.dark` toggled on the root element. Two states is a trap: a reader whose system is light and who picked light has no way back to "follow the system" when it changes. The terms are in `naf-terms.md` and the icons in `naf-icons.md`; the component is `naf-theme-toggle`.

**Print stays light.** A generated document keeps the light values whatever the reader's mode is — see the print and PDF exception above.

**No undocumented status.** Every status shown to a user must exist in `naf-terms.md` with a registered colour token and a registered icon. A status that appears in one screen without passing through the registry — however reasonable it looks — is the first step back to five different systems.

---

## 7. Copy

All user-facing text comes from `naf-terms.md` in the registry. Never invent a label.

- Buttons use the verbal noun: حفظ not احفظ
- Errors state what happened and what to do. They do not apologise.
- Empty states invite action. Never "لا توجد بيانات".
- Success messages name the action: تم الحفظ, تم الإرسال.
- The button that says نشر produces تم النشر, not تم الحفظ.

If a term is missing, add it to `naf-ui` first. Do not coin one locally.

---

## 8. Numbers, dates, money

Use the shared formatting library. Never format inline.

- Western digits always
- Currency in interfaces: the official Saudi Riyal symbol `U+20C1`, rendered by `Money` from `naf-currency`. Never the private-use `U+E900`, never the old `﷼` (U+FDFC), never typed into a string by hand.
- Currency in print and PDF: `12,400.00 ر.س`. Those files may be opened by software that does not load the symbol font, and an empty box is worse than an abbreviation. The same fallback appears automatically in the interface if the font fails to load.
- The symbol's height matches the height of the digits beside it, its clear space is a third of that height, and its direction follows the text. All three come from `naf-currency` — do not restyle it locally.
- The symbol font is pinned exactly, like Lucide. The height correction factor in `naf-currency.css` is measured against a specific release — ink height 62 against 73 for a digit in `@emran-alhaddad/saudi-riyal-font@1.1.0`. **Upgrading the package requires re-measuring and updating the factor. Never raise the pin without it.**
- Time: 24-hour
- Judicial dates — hearings, deadlines, statutory periods — show Gregorian followed by Hijri in parentheses. Invoices and internal timestamps stay Gregorian.
- Every number, date and amount wrapped in a direction-isolating element
- Table numerals tabular so columns align

---

## 9. Publishing and versioning

**A GitHub registry reads from the repository's default branch.** Work done on a feature branch is not published, no matter how complete it is. Nothing is live until it is merged into `main`.

**The version tag is a contract.** Once a release has been consumed by even one platform, its content is frozen. Any change after that requires a new version number. Re-tagging a consumed version gives two platforms different content under the same name — a silent failure, and the worst kind.

**Releases are automatic. Never create a tag by hand, and never move one.**

Merging into `main` runs the release workflow. It reads the commit subjects since the last tag, derives the number, creates the tag, publishes the release and regenerates `CHANGELOG.md`. A hand-made tag competes with it and breaks the contract above.

**Intent is written in the commit message.** That is the only place the version number comes from:

| Commit subject | Result |
|---|---|
| `fix: …` | patch — 1.2.3 → 1.2.4 |
| `feat: …` | minor — 1.2.3 → 1.3.0 |
| `feat!: …` or `BREAKING CHANGE:` in the body | major — 1.2.3 → 2.0.0 |
| `docs:` `refactor:` `chore:` `test:` `ci:` `style:` `build:` | nothing is released |

Use `.gitmessage` as the template — `git config commit.template .gitmessage` once per clone. Types outside the table are correct and expected; they simply do not trigger a release.

**The workflow refuses to publish a broken registry.** It runs `shadcn registry validate` and rebuilds `public/r` before anything else, and fails if the built output does not match `registry.json`. A release is never cut from a registry that does not validate.

**The same workflow ships to the platforms.** They have no `registry.json`, so the two registry steps are skipped there and only version derivation and changelog generation run. A platform release is cut from commit subjects exactly as the registry's is.

**Nothing is released when nothing warrants it.** A merge carrying only docs or refactors produces no tag and no release. That is the expected outcome, not a failure.

`CHANGELOG.md` is generated. Never edit it by hand — the next release overwrites the edit.

---

## 10. Definition of done

Before reporting any UI work complete:

1. Search the diff for raw values — no `#`, no `rgb(`, no arbitrary bracket values
2. Search the diff for `ml-|mr-|pl-|pr-|text-left|text-right|left-|right-` — must return nothing
3. Search the diff for emoji — must return nothing
4. Render in both `dir="rtl"` and `dir="ltr"`
5. Render in both light and dark
6. Tab through the screen — focus visible at every stop
7. Check at 375px width
8. Confirm every visible string exists in `naf-terms.md`
9. Confirm every icon exists in `naf-icons.md` with the same meaning
10. Confirm no number, date or amount is formatted inline — every one of them comes from `naf-format`
11. Confirm every amount renders through `Money` from `naf-currency`: symbol `U+20C1` (never `U+E900`, never `U+FDFC`), direction-isolated, tabular numerals, `ر.س` fallback intact

**State which of these you actually verified. Never claim a check you did not run.**

---

## 11. Working style

- One platform per session. Never two repos in one task.
- Migrations run in reviewable batches: propose the mapping table, get approval, then apply.
- Commit per batch so any batch can be reverted alone.
- Never delete a file.
- Never edit an original asset — copy it and edit the copy.
- When something is ambiguous, ask. Do not guess, do not proceed on an assumption.
- A table full of guesses is worth less than no table. If you cannot map something honestly, mark it low confidence and say so.
- Prefer boring, obvious code. Six codebases, many maintainers.
