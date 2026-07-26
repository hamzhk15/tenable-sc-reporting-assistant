---
name: vm-remediation-planning
description: Generate importable Tenable Security Center (Tenable SC / SecurityCenter) XML templates for a "Vulnerability Management and Remediation Planning" dashboard and/or report, then optionally upload them to a SC console via API keys. Use when a VM analyst or engineer wants to build, customize, or deploy a Tenable SC dashboard or report covering vulnerability trend, scanning history, risk by asset group or severity, top remediation opportunities, or detailed per-host / per-remediation remediation plans. Triggers on: "Tenable SC dashboard", "SecurityCenter report", "vulnerability management dashboard", "remediation planning report", "import SC template".
---

# Vulnerability Management & Remediation Planning — Tenable SC Template Generator

This skill builds **importable Tenable Security Center XML** for one template
family: **Vulnerability Management and Remediation Planning**. It produces a
dashboard, a report, or both, and can upload them to a SC console with API keys.

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

**Report** (`<report>`, type pdf, scVersion 6.6.0): About; Vulnerability
Overview (trend + severity pie); SLA Compliance (when SLAs are defined);
Understanding Risk (By-Severity matrix, By-VPR matrix, top remediation
opportunities, most vulnerable hosts — counts configurable, in that order); and
an optional **Detailed Remediation** chapter (configurable record count) that
iterates either:
- **by vulnerability** — each vulnerability → its affected hosts + remediation
  details; or
- **by host** — each host → its remediations + its vulnerabilities.

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
cd skills/vm-remediation-planning/scripts
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
