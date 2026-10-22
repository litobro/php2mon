---
name: php2mon
description: Amber-phosphor command console for the live worldwide PHP2Shell exploitation watch.
colors:
  bg: "#0b0f14"
  panel: "#0e141b"
  rail: "#090d12"
  ink: "#e8edf2"
  mut: "#9aa7b7"
  faint: "#7c8896"
  on-amber: "#0b0f14"
  rule: "rgba(134,149,166,.16)"
  rule2: "rgba(134,149,166,.30)"
  amber: "#f5a623"
  amber-dim: "#9a7324"
  red: "#ff5a5a"
  green: "#54cf96"
  blue: "#5cb0ff"
  danger-soft: "#e0894f"
typography:
  display:
    fontFamily: '"Martian Mono", ui-monospace, monospace'
    fontSize: "clamp(2.6rem, 7vw, 4.6rem)"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-.02em"
    fontFeature: "tabular-nums"
  headline:
    fontFamily: '"Martian Mono", ui-monospace, monospace'
    fontSize: "clamp(1.5rem, 3.4vw, 2.2rem)"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-.02em"
    fontFeature: "tabular-nums"
  title:
    fontFamily: '"Martian Mono", ui-monospace, monospace'
    fontSize: "11.5px"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: ".1em"
  body:
    fontFamily: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "-.01em"
    fontFeature: "tabular-nums"
  label:
    fontFamily: '"JetBrains Mono", ui-monospace, monospace'
    fontSize: "11px"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: ".13em"
  data:
    fontFamily: '"JetBrains Mono", ui-monospace, monospace'
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "normal"
    fontFeature: "tabular-nums"
rounded:
  none: "0"
  dot: "50%"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  xxl: "22px"
  gutter: "40px"
components:
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "16px"
  readout-hero:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.green}"
    typography: "{typography.display}"
    rounded: "{rounded.none}"
    padding: "22px 20px 20px"
  seg-button:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.mut}"
    rounded: "{rounded.none}"
    padding: "4px 11px"
  seg-button-active:
    backgroundColor: "{colors.amber}"
    textColor: "{colors.on-amber}"
    rounded: "{rounded.none}"
    padding: "4px 11px"
  sig-chip:
    backgroundColor: "transparent"
    textColor: "{colors.red}"
    rounded: "{rounded.none}"
    padding: "1px 6px"
  status-tag-ok:
    backgroundColor: "transparent"
    textColor: "{colors.green}"
    rounded: "{rounded.none}"
    padding: "2px 7px"
  status-tag-alert:
    backgroundColor: "transparent"
    textColor: "{colors.red}"
    rounded: "{rounded.none}"
    padding: "2px 7px"
  theme-btn:
    backgroundColor: "transparent"
    textColor: "{colors.mut}"
    rounded: "{rounded.none}"
    padding: "3px 8px"
  theme-btn-hover:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "3px 8px"
  magnitude-bar:
    backgroundColor: "{colors.amber}"
    rounded: "{rounded.none}"
    height: "3px"
---

# Design System: php2mon

## Overview

**Creative North Star: "The Amber-Phosphor Watch Floor"**

php2mon reads as an instrument panel on watch, not a SaaS metrics dashboard. The surface is a single standing console for one question — is PHP2Shell being exploited in the wild right now, and from where — and every decision serves comprehension under pressure. Density, precision, and semantic restraint carry the tension; nothing blooms, glows, or decorates. The ground is a deep slate-ink (#0b0f14, never pure black), lit by a single amber phosphor and read through monospaced type and tabular numerals. Dark is the primary world; light is a true paper-ink inverse (#e8ecf0 ground) reached by `prefers-color-scheme` or a persisted manual toggle.

The layout is a stack of ruled regions divided by hairline 1px low-alpha bezels — a sticky status rail, a row of instrument readouts, then ruled panels for the timeline, the IoC table, top sources, patch adoption, and a claims log. There are no rounded cards, no shadows, no gradients, no glass. Depth is drawn entirely by rules and by three flat background planes (rail < bg < panel). Color is rationed: amber is the one structural accent, red is held in reserve for genuine exploitation, green means all-clear, and the vast remainder of the screen is neutral.

The build deliberately refuses two clichés named in its brief: the same-size icon-number-label card grid, and the neon-cyberpunk glow. It also treats a zero as the good, watched state — calm green "ALL CLEAR", never an error. Motion is almost absent by design: exactly two semantic moments exist, both gated behind `prefers-reduced-motion`.

**Key Characteristics:**
- Flat instrument panel: 0 radius, no shadows, no gradients, hairline rules as bezels.
- One amber accent; red reserved strictly for exploit-confidence signals.
- Monospace throughout (Martian Mono display, JetBrains Mono data), tabular numerals, uppercase tracked labels.
- Dark-primary with a paper-ink light inverse; theme persisted in localStorage.
- Two motion moments only (refresh ping, alert pulse), both reduced-motion-gated.

## Colors

A rationed, semantic palette: three neutral background planes and three neutral text weights carry almost the whole screen, with amber as the only structural accent and red/green/blue as reserved signal colors. All values below are the dark-mode (primary) canon; the light inverse is given in parentheses where it diverges meaningfully.

### Primary
- **Signal Amber** (`#f5a623`, light `#9a5b00`): the single structural accent. Carries live/attention everywhere it is earned — the `//` panel-header prefixes, the active segmented-toggle fill, magnitude bars, link underlines, selection highlight, focus ring, the patch-release timeline marker, and the all-feeds-down pulse fallback.

### Secondary
- **Exploit Red** (`#ff5a5a`, light `#c22f2a`): reserved strictly for genuine exploitation signals — the exploit-confidence timeline line, signature chips, the ACTIVE tag, alert readout values, exploit-hit counts, and the KEV marker. It never appears for generic scanning.
- **All-Clear Green** (`#54cf96`, light `#1d8a5c`): the calm/healthy state — the LIVE word, the online pulse dot, healthy feed dots, the zero-state hero value, and the ALL CLEAR tag.

### Tertiary
- **Context Blue** (`#5cb0ff`, light `#1f6fd0`): a single low-weight contextual marker — the Cloudflare-rules vertical marker on the timeline. Not a general-purpose accent.
- **Danger-Soft Ember** (`#e0894f`, light `#b5663a`): the non-exploit "vulnerable" series in the patch-adoption chart; a muted warning distinct from reserved red.

### Neutral
- **Slate-Ink Ground** (`--bg` `#0b0f14`, light `#e8ecf0`): the page ground. Never pure black.
- **Panel** (`--panel` `#0e141b`, light `#ffffff`): the raised plane for ruled panels and table bodies.
- **Rail** (`--rail` `#090d12`, light `#f3f5f8`): the recessed plane for the sticky status rail and chart tooltips.
- **Ink** (`--ink` `#e8edf2`, light `#121922`): primary text and the live counter.
- **Muted** (`--mut` `#9aa7b7`, light `#4a5663`): labels, secondary text, the all-hits timeline line, chart ticks.
- **Faint** (`--faint` `#7c8896`, light `#515b67`): captions, zero-value figures, timestamps, skeletons.
- **On-Amber** (`--on-amber` `#0b0f14`, light `#ffffff`): text on amber fills.
- **Rule / Rule2** (`rgba(134,149,166,.16)` / `.30`; light `rgba(18,25,34,.13)` / `.24`): the hairline bezels — `rule` for interior dividers, `rule2` for region edges.

### Named Rules
**The Reserved Red Rule.** `--red` is spent only on exploit-confidence signals. Generic scan traffic, totals, and context stay neutral (`--mut` / `--faint`). If a surface would color ordinary scanning red, it is wrong.

**The One Accent Rule.** Amber is the only structural accent. A screen should read neutral with amber used sparingly for liveness and selection; a second decorative accent breaks the world.

**The Zero Is Calm Rule.** A zero exploit count renders green with the ALL CLEAR tag and a "watch active" subline — never red, never an error, never missing-data styling.

## Typography

**Display Font:** Martian Mono (fallback `ui-monospace, monospace`) — weights 500 and 700, self-hosted woff2.
**Body / Data Font:** JetBrains Mono (fallback `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`) — weights 400 and 700, self-hosted woff2.

**Character:** A two-monospace pairing. Martian Mono is wide, geometric, and stencil-like; it is used only for the masthead and the big readouts so the numbers that matter read as machine output. JetBrains Mono carries every telemetry figure, table, and body line. Everything is tabular-numeral and the whole surface runs at a slightly negative tracking (`-.01em`) except labels, which are tracked wide and set uppercase.

### Hierarchy
- **Display** (Martian Mono 700, `clamp(2.6rem, 7vw, 4.6rem)`, line-height 1, `-.02em`): the hero exploit-confidence readout only.
- **Headline** (Martian Mono 700, `clamp(1.5rem, 3.4vw, 2.2rem)`, line-height 1): the secondary readout values (hits/24h, unique sources, Radar L7).
- **Title** (Martian Mono 500, 11.5px, `.1em`, uppercase): panel `// TITLE` headers and the masthead brand.
- **Body** (JetBrains Mono 400, 14px / 1.5, `-.01em`, tabular-nums): default text.
- **Label** (JetBrains Mono 400, 11px, `.13em`, uppercase): readout keys, table headers, tags, empty-state headings.
- **Data** (JetBrains Mono, 12.5px, tabular-nums): table cell figures.

### Named Rules
**The Two-Font Division Rule.** Martian Mono is for the masthead and hero readouts only; every telemetry figure, table, and chart label is JetBrains Mono. Do not set body copy or table data in the display face.

**The Tracked-Label Rule.** Any label, key, or header is uppercase and letter-spaced (`.1em`–`.13em`); numeric readouts and data are tight (`-.01em`/`-.02em`) and tabular. The contrast between tracked labels and tight figures is the type signature.

## Layout

A single centered column, `max-width: 1180px`, 20px side gutters (14px below 560px). The surface is a vertical stack of ruled regions, not a free card grid.

- **Status rail:** sticky, full-bleed, `position: sticky; top: 0`, a 3-column grid (`1fr auto 1fr`) — brand left, live cluster centered, feed-health + theme right. Below 560px it collapses to a stacked flex column.
- **Readouts row:** a 4-column grid `1.5fr 1fr 1fr 1fr` with the hero in the wide first cell, divided by interior vertical rules. Collapses to 2 columns at 860px (hero spans full width).
- **Panels:** full-width ruled blocks stacked with shared borders (`border-top: 0` on adjacent panels so rules never double). The "Top sources / Patch adoption" pair uses a 2-column `.split` that collapses to one column at 860px.
- **Spacing rhythm:** panel bodies pad 16px; readouts pad `22px 20px 20px`; rail pads `11px 20px`; interior gaps run 6/10/12/14/16px. The scale is loose and functional, not a strict modular ramp.
- **Breakpoints:** 860px (grids collapse) and 560px (rail stacks, non-essential IoC columns `c-asn`/`c-total`/`c-last` hide so IP, geo, signatures, and exploit count stay on-screen without horizontal scroll).

## Elevation & Depth

**No shadows. No gradients. No blur.** The system is strictly flat — there is not a single `box-shadow`, `linear-gradient`, or `backdrop-filter` in the build. Depth is conveyed two ways only: by three flat background planes (recessed `--rail` < ground `--bg` < raised `--panel`) and by hairline 1px low-alpha rules (`--rule` interior, `--rule2` edges) that act as instrument bezels.

### Named Rules
**The Hairline Bezel Rule.** Regions are separated by 1px low-alpha rules, never by shadow, radius, or fill contrast alone. Adjacent panels collapse their shared border (`border-top: 0`) so a divider is always exactly one hairline thick.

## Shapes

Right angles everywhere. `border-radius: 0` is the law for every rectangular element — panels, chips, tags, bars, the segmented toggle, buttons, even the scrollbar thumb. The only curved shapes are the status indicators: the live pulse and the feed-health dots are perfect circles (`border-radius: 50%`), which reads as an instrument LED rather than a card corner. Borders are uniformly 1px and low-alpha; there is no clipping, no inset, no outline decoration beyond the amber focus ring.

## Components

### Status rail (signature)
- **Character:** the persistent frame — a sticky header that proves the watch is live.
- **Contents:** brand `PHP2SHELL // GLOBAL EXPLOITATION WATCH` (amber `//`), a centered live cluster (pulse dot + `LIVE` + `PATCH +HH:MM:SS` counter ticking every second), and a right cluster of `FEEDS n/N` with one colored dot per collector (green ok / amber stale / red error).
- **Behavior:** the pulse dot pings once per successful 60s refresh; its base color is green when any feed is healthy, amber when all feeds are down.

### Instrument readouts (signature)
- **Shape:** flat grid cells divided by vertical rules; no card, no radius, no icon.
- **Hero:** exploit-confidence hits in display face at `clamp(2.6rem,7vw,4.6rem)`. Green with `ALL CLEAR` tag at zero; red with `ACTIVE` tag and a reduced-motion-gated opacity pulse when above zero.
- **Secondary readouts:** headline-size values, muted uppercase key, faint subline.

### Panels / Containers
- **Corner Style:** square (0 radius).
- **Background:** `--panel`; header row divided by a `--rule` hairline.
- **Header:** `// TITLE` in display 500, 11.5px, uppercase, `.1em` tracked, amber `//` prefix (CSS `::before`), optional faint meta on the right.
- **Border:** 1px `--rule`; shared borders collapse between stacked panels.
- **Internal padding:** 16px body, `12px 16px` header.

### Segmented toggle (window control)
- **Style:** inline-flex, 1px `--rule2` outer border, dividers between buttons; uppercase 11px, `.08em` tracked.
- **State:** the pressed button (`aria-pressed="true"`) fills amber with on-amber text, weight 700; others are muted on panel.

### Chips
- **Signature chip (`.sig`):** 11px, red text, 1px red border, square, transparent fill — one per exploit signature on an IoC row. Red because signatures are exploit-confidence evidence.
- **Status tag (`.tag`):** 11px uppercase, 1px `currentColor` border, square; `.ok` green / `.alert` red.

### Tables
- **Style:** full-width, collapsed borders, 12.5px data, tabular-nums; headers 11px uppercase `.1em` muted. Rows divided by `--rule`; hover tints the row with `--rule`. IoC IP cell is bold ink; context cells muted.
- **Magnitude bar (`.bar`):** a 3px amber bar under the exploit-hit count, width scaled to the row's share of the window max — an inline sparkline, not a separate chart.
- **Figures:** exploit counts use red bold (`.num-alert`); zero/absent values use faint (`.num-zero`).

### Buttons
- **Theme button:** ghost — transparent fill, muted text, 1px `--rule` border, uppercase 11px `.1em`, square. Hover lifts text to `--ink` and border to `--rule2`. No other persistent buttons exist; the surface is a monitor, not a console.

### Charts (phosphor timelines)
- **Defaults:** JetBrains Mono 10px, animation disabled, low-alpha grid (`--rule`), muted ticks.
- **Timeline:** exploit-confidence as a solid 2px red line; all-hits as a 1px muted dashed line; no fill. Event markers are vertical dashed 1px rules with a small label — patch release (amber), embargo (amber), CF rules (blue), KEV (red).
- **Adoption:** fixed as green, vulnerable as danger-soft ember; both 2px, no fill.
- **Empty states:** a calm centered block — `NO EXPLOIT-CONFIDENCE SOURCES` (green, all-clear) or `NO DATA` with a plain-language reason, never an error treatment.

## Do's and Don'ts

### Do:
- **Do** keep red exclusively for exploit-confidence signals; color generic scan traffic with `--mut` / `--faint`.
- **Do** present a zero exploit count as calm green `ALL CLEAR` with a "watch active" subline.
- **Do** divide regions with 1px low-alpha hairline rules and collapse shared borders between stacked panels.
- **Do** set the masthead and hero readouts in Martian Mono and every figure, table, and chart label in JetBrains Mono, all tabular-nums.
- **Do** keep uppercase labels tracked (`.1em`–`.13em`) and numeric readouts tight (`-.01em`/`-.02em`).
- **Do** gate every animation behind `prefers-reduced-motion: no-preference` and limit motion to the refresh ping and the alert-state pulse.

### Don't:
- **Don't** use `border-radius` on any rectangular element; only status indicator dots are circles.
- **Don't** introduce `box-shadow`, gradients, glass/blur, or any glow — the panel is strictly flat.
- **Don't** add a second structural accent; amber is the only one.
- **Don't** use `#000` pure black as a ground; the dark ground is `#0b0f14`.
- **Don't** render an all-clear or missing-data state as an error (red, warning icon, empty-slot styling).
- **Don't** set body copy, table data, or chart labels in the display face.
