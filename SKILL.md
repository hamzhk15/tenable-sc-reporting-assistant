---
name: tenable-sc-reporting-assistant
description: Generate importable Tenable Security Center (Tenable SC / SecurityCenter) XML for dashboards, PDF reports, and CSV exports, then optionally upload them to a SC console via API keys. Works two ways — a freeform mode that maps any dashboard/report a user describes to a catalog of known-good components, proposes the layout for approval, and builds it with tested builders; and a curated "Vulnerability Management and Remediation Planning" dashboard/report as a ready-made starting point. Use whenever someone wants to build, customize, or deploy a Tenable SC dashboard or report of any kind — vulnerability trend, scanning history, risk by asset group / severity / VPR, SLA compliance, top remediation opportunities, per-host or per-vulnerability breakdowns, custom matrices/tables/charts, or any combination. Triggers on: "Tenable SC dashboard", "SecurityCenter report", "vulnerability management dashboard", "custom SC dashboard", "SC report template", "import SC dashboard/report".
---

# Tenable SC Reporting Generator — dashboards, reports & CSV exports

This skill builds **importable Tenable Security Center XML** — dashboards, PDF
reports, and CSV exports of essentially any composition — and can upload them to
a SC console with API keys. It ships a curated Vulnerability Management &
Remediation Planning template as a ready-made starting point, and a freeform
mode for building whatever the user describes from a catalog of tested
components.

## Two ways to use it

Pick the mode from what the user asks for:

- **Freeform mode:** the user describes any dashboard or report in their own
  words ("show me exploitable criticals by asset group over 90 days, plus a
  top-10 remediation table and a CSV of everything"). You **map the request to
  the component catalog** (`references/component-catalog.md`), **propose the
  component list for the user to confirm**, then build it by composing the
  tested builders — never by hand-writing XML. See "Freeform mode" below. This
  is the general path: any Tenable SC dashboard/report the catalog's recipes can
  express.
- **Curated mode:** the ready-made **Vulnerability Management and Remediation
  Planning** dashboard/report described under "What it produces" — a good
  default when the user just wants a solid VM dashboard/report without
  specifying components. Run the interview, generate, validate, deliver.

Both modes converge on the same pipeline: build via the `sc_dashboard` /
`sc_report` builders → **always** `validate.py` → deliver or upload. Every
correctness rule (cluster counts, colors, severity scoping, byte-accurate
serialization) is enforced there, so both modes inherit the same guarantees.

## What it produces

**Dashboard** (`<dashboardTab>`, scVersion 6.2.0):
1. **Vulnerability Trend Over Time** — line chart, one series per tracked severity.
2. **Scanning History** — matrix: assets scanned (plugin 19506), vulnerabilities
   detected (last observed), and vulnerabilities mitigated — across Last Day /
   Week / Month / Quarter / Year.
3. **Understanding Risk – By Asset Group** — matrix (only when the user filters
   by 2–10 asset groups): one row per group, columns = Total Assets, Mitigated,
   Unmitigated, Exploitable, Exploitable+Patch>30d, Hosts w/ Exploitable Patch>30d.
4. **Understanding Risk – By Severity** — same columns, one row per tracked
   severity plus a total row.
5. **Understanding Risk – By VPR** — same columns, one row per VPR band
   (Critical 9.0–10 / High 7.0–8.9 / Medium 4.0–6.9 / Low 0.1–3.9) plus a
   total row. VPR is threat-based priority, not fixed CVSS severity.
6. **Vulnerability SLA Compliance** — matrix (only when SLAs are defined):
   one row per severity (labeled with its SLA days), columns = Total
   Unmitigated / Within SLA / Overdue.
7. **Understanding Risk – Remediation Opportunities** — table, top 10 solutions.

Reports describe the applied filters in a paragraph, but dashboards have no such
place — so the dashboard **name and every component header carry a compact scope
tag**, e.g. `[Active · 90d · AG:3,9,14 · CHML]` (data source · freshness window ·
repos/asset-groups · severity initials). This makes the active filters legible at
a glance without opening each widget.

**Report** (`<report>`, type pdf, scVersion 6.6.0): About; Vulnerability
Overview (trend + severity pie); SLA Compliance (when SLAs are defined);
Understanding Risk (By-Severity matrix, By-VPR matrix, top remediation
opportunities, most vulnerable hosts — counts configurable, in that order); and
an optional **Detailed Remediation** chapter (configurable record count) that
iterates either:
- **by vulnerability** — each vulnerability → the hosts it affects; or
- **by host** — each host → the remediations it needs.

(Only the complementary breakdown is shown inside the loop — a per-host vuln
dump under a by-host grouping, or per-vulnerability details under a
by-vulnerability grouping, would just restate the row and is omitted.)

Optionally, a companion **CSV report** (`<report>`, type csv, styleFamily 5): a
flat, analysis-ready vulnerability export (list-style `vulndetails`, ~37
columns) using the same detailed-remediation filters chosen for the PDF.

## How to use this skill

### Step 1 — Interview the user

Ask these questions (use the AskUserQuestion tool where it helps; group them).
Every answer maps to a key in the config JSON (see `references/config-schema.md`).

1. **Dashboard, report, or both?** → `artifact`
2. **Which vulnerability data — active only, or everything?** → `vuln_data`
   (`active` adds `pluginType=active` globally; `all` includes passive/other.)
3. **Data freshness — Last Day / Week / Month / Quarter (90d) / Year (365d) / all data?** → `data_freshness`
4. **Which severities to track — Critical / High / Medium / Low?** → `severities`
   (**Never include Info** — Info findings are scan metadata, not vulnerabilities.)
5. **SLAs defined?** If yes, days for Critical/High/Medium/Low. → `sla`
6. **Detailed remediation grouped by Vulnerability or by Host?** → `group_remediation_by`
   (SC supports iterating the detailed section by vulnerability or by host —
   grouping by remediation solution is not supported.)
7. **Filter by repository IDs?** If yes, which. → `repository_ids`
8. **Filter by asset group IDs?** If yes, which. → `asset_group_ids`
   (2–10 groups enables the By-Asset-Group matrix.)

> **Asset-group rows must show the real group name, never "Asset Group N".**
> - If the IDs came from the console (via `list_scope.py` / `--resolve-names`),
>   use the real names automatically.
> - If the user typed IDs manually, **ask for each group's name, one by one**,
>   and put them in `asset_group_labels` (`{"3":"Windows Hosts", ...}`).
> `generate.py` warns if any asset group is left without a real name.

> **Never substitute placeholder IDs.** If the user says they want to filter by
> repository or asset-group IDs, you MUST stop and collect the actual IDs before
> generating — either by asking them, or by listing them from their console with
> `list_scope.py` (below). Generating with made-up IDs is a failed run.
9. *(Report only)* **Include the Detailed Remediation section?** → `detail_enabled`
   If yes:
   - **How many records — 10 / 20 / 50 / 100 / all?** → `detail_max`
   - **Detailed section: exploitable vulns only?** → `detail_exploitable_only`
   - **Detailed section: critical vulns only?** → `detail_critical_only`
10. *(Report only)* **Most Vulnerable Hosts — how many: 10 / 20 / 50 / 100 / all?** → `top_hosts_max`
11. *(Report only)* **Top Remediation Opportunities — how many: 10 / 20 / 50 / 100 / all?** → `top_remediation_max`
12. *(Report only)* **Also generate a CSV vulnerability export?** → `csv_report`
    (A flat, filtered vulnerability list alongside the PDF, using the same
    detailed-remediation filters.)

If the user wants to filter by repository or asset group but doesn't know the
IDs, offer to list them from their console (requires the SC URL + API keys):

```bash
export TSC_HOST=sc.example.com TSC_ACCESS_KEY=... TSC_SECRET_KEY=...
python3 list_scope.py            # both; add --repos or --asset-groups to narrow
python3 list_scope.py --insecure # self-signed lab consoles
```

It prints each repository and asset group with its **ID** and name so the user
can pick which IDs to put in `repository_ids` / `asset_group_ids`. In SC, an
"asset group" is an asset list (served from `/rest/asset`).

### Step 2 — Write the config and generate

Write the answers to a `config.json` (schema in `references/config-schema.md`), then:

```bash
cd scripts
python3 generate.py --config /path/to/config.json --out-dir /path/to/output
```

(Or `python3 generate.py --interactive` to prompt directly.)

### Step 3 — Validate (always)

```bash
python3 validate.py "/path/to/output/"*.xml
```

This catches every known import-failure class: malformed XML, PHP byte-prefix
mismatches, invisible fg==bg colors, missing table `<schedule>`, Info-severity
filters, and `sumip` host cells that wrongly default to `vulnCount`. **Do not
deliver a file that fails validation.**

### Step 4 — Deliver or upload

- **Manual import** (default): hand the user the XML file(s). In SC:
  - Dashboard → *Dashboard > Options > Add Dashboard > Import*
  - Report → *Reporting > Report Templates > Options > Import*
- **Automatic upload**: if the user provides a console URL + API keys, use
  `upload.py` (stdlib-only; talks to the SC REST API directly — no third-party
  packages). Never hard-code credentials; pass them via env vars or flags and
  confirm with the user before uploading to a live console. Use `--insecure`
  only for self-signed lab consoles.

```bash
export TSC_HOST=sc.example.com TSC_ACCESS_KEY=... TSC_SECRET_KEY=...
python3 upload.py --dashboard "…- Dashboard.xml" --report "…- Report.xml"
# add --csv "…- Detailed Vulnerabilities.xml" to import the CSV export too
```

### Step 5 — Tell the user about first-load "No Data" widgets

After import, **some widgets may show "No Data" / not populate until they are
re-saved once.** This is a known Tenable SC behavior: the imported component
doesn't get queried until its definition is (re)committed. If the user reports
an empty or stuck widget, tell them to:

1. On the dashboard, click the widget's gear/options → **Edit**.
2. Open any one of its filters, change it and change it back (or just re-select
   the same value) so the form registers a change.
3. **Submit / Save.** The widget then runs its query and populates.

Repeat per affected widget. This does not indicate a bad template — the XML is
correct; SC just needs the definition re-committed once after import.

## Freeform mode

Use this when the user wants something other than the curated template — a
custom dashboard or report described in their own words ("give me a dashboard of
exploitable criticals by asset group over the last 90 days, plus a top-10
remediation table"). The goal is to satisfy the request **by composing the same
tested builders** — never by hand-writing XML, which is exactly how every bug in
`references/sc-xml-format.md` was introduced.

**Step F1 — Elicit the request and the scope.** Get two things:
- *What* they want to see (the components / questions to answer).
- The *scope* — the same global filters the curated interview collects:
  `vuln_data`, `data_freshness`, `severities`, `repository_ids`,
  `asset_group_ids` (+ real names), and any SLAs. Scope still flows through the
  global-filter injector `gf` and drives the dashboard scope tag, so collect it
  even in freeform mode. The "never substitute placeholder IDs" and
  "asset-group rows show the real name" rules from Step 1 apply unchanged.

**Step F2 — Map the request to the catalog.** Open
`references/component-catalog.md` and translate each thing the user asked for
into a catalog recipe using the "Mapping user intent → recipes" heuristics
(trend → line chart / time-window matrix; by-severity/VPR/asset-group →
Understanding-Risk matrix; top-N → table; SLA → SLA matrix; per-host /
per-vuln → report iterator; export → CSV). Carry the row-scoping rules with you
(VPR / asset-group rows MUST also carry the severity filter).

**Step F3 — Propose the component list and get approval.** Before building,
present the mapped component list back to the user for confirmation — e.g.:

> I'll build a dashboard with:
> 1. Understanding Risk – By Asset Group (matrix) — exploitable criticals only
> 2. Remediation Opportunities (table, top 10)
>
> Scope: Active data, 90d, severities Critical+High, asset groups 3/9/14.

Use AskUserQuestion (or plain text) and adjust until they approve. If any request
maps to **no** catalog recipe, say so plainly: offer the closest recipe, or state
that a new tested builder must be written and validated first — do **not**
improvise raw XML to cover the gap.

**Step F4 — Build by composing builders.** Assemble the approved components with
the `sc_dashboard` / `sc_report` builder functions listed in the catalog
(`matrix`/`table`/`linechart` + `add` for dashboards; `report_matrix`/
`table_component`/`iterator` + `chapter`/`group` for reports; `write_csv_report`
for CSV). Always route each cell's base filters through `gf`. For anything the
curated pipeline already parameterizes, prefer extending the config over writing
a one-off — but a bespoke composition in a small driver script is fine as long
as it only calls tested builders.

**Step F5 — Validate, then deliver or upload.** Exactly as curated mode:
`validate.py` on every generated file (it enforces the cluster-count, color,
schedule, Info-severity and host-cell rules), then hand over the XML or
`upload.py` it. Never deliver a file that fails validation.

The one inviolable rule of freeform mode: **it only ever composes catalog
recipes / tested builders.** If you catch yourself about to construct a
`<definition>` by hand, stop — that path reintroduces the byte-prefix, cluster,
and cell-shape bugs the builders exist to prevent.

## Critical correctness rules (baked into the scripts — respect them)

- **Definitions are base64(PHP-serialized) with UTF-8 *byte*-length prefixes.**
  Always generate via the scripts; never hand-edit a `<definition>`.
- **Info (severity 0) is excluded everywhere.** It is not a vulnerability.
- **Host counts use `sumip` + `outputText=ipCount`.** Vuln counts use `sumid`.
- **`outputColors` is `foreground:background`.** fg==bg is invisible.
- **Table components need a `<schedule>`; matrices embed it per cluster.**
- Prefer structured filters (`assetID`, `repositoryIDs`, `severity`,
  `exploitAvailable`, `patchPublished`) over keyword matching.

See `references/` for the full format spec, filter/tool vocabulary, and config schema.
