# UI/UX Design Document
## Product: CodeSentry

---

### 1. Design Principles

- **Signal over noise**: severity color-coding must dominate visual hierarchy — a reviewer should identify Critical findings within 2 seconds of landing on any findings list.
- **Evidence-first**: every finding shows the actual code snippet inline, never just a rule name — reduces round-trips to source.
- **Trust through transparency**: always show which tool/rule produced a finding (Semgrep rule ID / OSV advisory ID) — critical for a security tool's credibility.

### 2. Visual System

- **Theme**: dark-mode-first (standard for security/dev tooling — SIEMs, SAST dashboards, terminals all default dark; reduces eye strain for long review sessions)
- **Severity color scale** (consistent everywhere — dashboard, list, detail, report):
  - Critical: `#DC2626` (red)
  - High: `#EA580C` (orange)
  - Medium: `#D97706` (amber)
  - Low: `#65A30D` (green-ish, low alarm)
  - Info: `#6B7280` (neutral gray)
- **Typography**: UI text — Inter (clean, high legibility at small sizes for dense tables); Code snippets — JetBrains Mono or Fira Code (ligature-free security context, monospace clarity)
- **Layout grid**: 12-column responsive, max content width 1440px, dashboard cards on 4/8 split (summary sidebar + main content)

### 3. Key Screens

**3.1 Dashboard**
- Top: global stats bar (Total Projects, Total Findings by severity, Last Scan timestamp)
- Main: project cards, each showing mini severity bar chart + last scan status badge
- Empty state: clear CTA "+ New Project" with brief explainer, not a blank void

**3.2 Scan Detail / Findings List**
- Left rail: filter panel (severity checkboxes, CWE search, OWASP category dropdown, triage status filter)
- Main: table view — columns: Severity | Rule/CWE | File:Line | Status | Snippet preview (truncated)
- Sortable by severity (default), file path, or status
- Row click → slide-over panel (not full navigation away) for Finding Detail — keeps list context

**3.3 Finding Detail (slide-over panel)**
- Header: severity badge + CWE ID + OWASP category tag
- Code viewer: syntax-highlighted snippet, offending line highlighted, 5 lines of context above/below — rendered via a text-safe code component (mitigates T7 stored-XSS risk from TRD, never raw HTML injection)
- Description: what the vulnerability is, in plain language
- Remediation: concrete fix guidance (code-level where possible)
- Triage controls: status dropdown (Confirmed/False Positive/Won't Fix/Needs Review) + notes textarea + "Save" — autosave on blur with visible saved-state indicator
- Audit trail: mini log of who changed status and when

**3.4 Report Export View**
- Preview pane mirrors final PDF/MD structure before download
- Toggle: "Include all findings" vs "Confirmed only" (default: confirmed only, to avoid shipping scanner noise as if it were reviewed fact)
- Download buttons: PDF / Markdown

**3.5 Settings**
- Ruleset toggles (which Semgrep packs run) with plain-language descriptions, not just pack IDs
- Account/API key management

### 4. Accessibility & Usability Notes

- All severity indicators paired with text label, not color alone (colorblind accessibility — never rely on red/green distinction only)
- Keyboard navigable findings list (arrow keys + enter to open detail) — reviewers triaging dozens of findings need speed
- Loading states for every async action (scan trigger, report export) — never a silent spinner-less wait, given scans can take minutes
