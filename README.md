# tenable-sc-reporting-assistant

A **Claude skill** that generates importable **Tenable Security Center (Tenable
SC / SecurityCenter)** XML for **dashboards, PDF reports, and CSV exports** —
and optionally uploads them to a SC console via API keys, talking directly to
the SC REST API (no third-party dependencies).

It works two ways:

- **Freeform** — describe any dashboard or report you want; the skill maps your
  request to a catalog of tested components, proposes the layout for approval,
  and builds it by composing known-good builders (never hand-written XML).
- **Curated** — a ready-made **Vulnerability Management & Remediation Planning**
  dashboard/report as a solid starting point.

## What the curated template generates

(Freeform builds arbitrary combinations of the same component types — matrices,
tables, line/pie charts, iterators, CSV exports — see
[`references/component-catalog.md`](references/component-catalog.md).)

**Dashboard**
- Vulnerability Trend Over Time (line chart)
- Scanning History (assets scanned via plugin 19506; vulns detected; vulns
  mitigated — across Last Day / Week / Month / Quarter / Year)
- Understanding Risk – By Asset Group (matrix, for 2–10 asset groups)
- Understanding Risk – By Severity (matrix)
- Understanding Risk – By VPR (matrix, rows by VPR band)
- Vulnerability SLA Compliance (matrix, when SLAs are defined)
- Understanding Risk – Remediation Opportunities (top 10 table)

**Report** (PDF template)
- About, Vulnerability Overview (trend + severity), Understanding Risk
  (remediation opportunities + most vulnerable hosts — record counts configurable)
- Detailed Remediation (optional; configurable record count) — grouped
  **by vulnerability** (each vuln → the hosts it affects) or
  **by host** (each host → the remediations it needs)

**CSV export** (optional) — a flat, analysis-ready vulnerability list (CSV
report, ~37 columns) generated alongside the PDF using the same
detailed-remediation filters.

The generator asks about artifact type, active-vs-all data, data freshness,
severities, SLAs, remediation grouping, repository filter, asset-group filter,
and (for reports) whether to include the Detailed Remediation section, the
record counts for the detailed / most-vulnerable-hosts / top-remediation
sections, exploitable-only / critical-only detail scoping, and whether to also
emit the CSV export.

## Repository layout

```
.
├── SKILL.md                     # skill entry point (interview + workflow)
├── references/
│   ├── config-schema.md         # config.json schema
│   ├── component-catalog.md     # tested component recipes (freeform mode)
│   └── sc-xml-format.md         # SC XML format spec & correctness rules
└── scripts/
    ├── sc_common.py             # byte-accurate PHP (de)serializer + palette
    ├── sc_dashboard.py          # dashboard component builders
    ├── sc_report.py             # report chapter/group/iterator builders
    ├── generate.py              # config → XML (CLI, --config or --interactive)
    ├── validate.py              # pre-flight import checks
    ├── list_scope.py            # list repository & asset-group IDs from a console
    ├── upload.py                # stdlib REST import into a live console
    └── config.example.json      # sample config
```

## Quick start (standalone, without Claude)

```bash
cd scripts

# (optional) list repository & asset-group IDs from your console to filter by
export TSC_HOST=sc.example.com TSC_ACCESS_KEY=... TSC_SECRET_KEY=...
python3 list_scope.py --insecure

# generate from a config file …
python3 generate.py --config config.example.json --out-dir ./out
# … or answer prompts interactively
python3 generate.py --interactive

# always validate before importing
python3 validate.py ./out/*.xml

# optional: upload straight into a console via the SC REST API
export TSC_HOST=sc.example.com TSC_ACCESS_KEY=... TSC_SECRET_KEY=...
python3 upload.py --dashboard "./out/VM Remediation Planning - Dashboard.xml"
# add --report / --csv to import the PDF report and CSV export too
# add --insecure for self-signed lab consoles
```

Everything uses only the Python standard library — no `pip install`, no
third-party dependencies.

## Using it as a Claude skill

Copy this repository into your Claude skills directory as
`~/.claude/skills/tenable-sc-reporting-assistant/`, or point your project at
this repo. Claude will
invoke it when you ask to build or deploy a Tenable SC dashboard or report of
any kind, map your request to tested components (or run the curated interview),
generate the XML, validate it, and either hand you the files or upload them with
credentials you provide.

## Correctness

SC stores each `<definition>` as base64(PHP-serialized) with UTF-8 **byte**-length
prefixes, so these files must be generated, never hand-edited. `validate.py`
checks base64/round-trip integrity, invisible `fg==bg` colors, missing table
schedules, `sumip` host-count mistakes, and accidental Info-severity filters.
See [`references/sc-xml-format.md`](references/sc-xml-format.md).

## License

MIT — see [LICENSE](LICENSE).
