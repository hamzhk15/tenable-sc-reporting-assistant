# tenable-sc-reporting-assistant

A **Claude skill** that helps Vulnerability Management (VM) analysts and
engineers generate importable **Tenable Security Center (Tenable SC /
SecurityCenter)** XML templates for a **Vulnerability Management and Remediation
Planning** dashboard and/or report — and optionally upload them to a SC console
via API keys, talking directly to the SC REST API (no third-party dependencies).

## What it generates

**Dashboard**
- Vulnerability Trend Over Time (line chart)
- Scanning History (assets scanned via plugin 19506; vulns detected; vulns
  mitigated — across Last Day / Week / Month / Quarter / Year)
- Understanding Risk – By Asset Group (matrix, for 2–10 asset groups)
- Understanding Risk – By Severity (matrix)
- Understanding Risk – Remediation Opportunities (top 10 table)

**Report** (PDF template)
- About, Vulnerability Overview (trend + severity), Understanding Risk (top-10
  remediation + top-20 hosts)
- Detailed Remediation — grouped **by remediation** (each solution → its vulns +
  affected hosts) or **by asset** (each host → its remediations + its vulns)

The generator asks about artifact type, active-vs-all data, data freshness,
severities, SLAs, remediation grouping, repository filter, asset-group filter,
and (for reports) exploitable-only / critical-only detail scoping.

## Repository layout

```
skills/vm-remediation-planning/
├── SKILL.md                     # skill entry point (interview + workflow)
├── references/
│   ├── config-schema.md         # config.json schema
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
cd skills/vm-remediation-planning/scripts

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
# add --insecure for self-signed lab consoles
```

Everything uses only the Python standard library — no `pip install`, no
third-party dependencies.

## Using it as a Claude skill

Copy `skills/vm-remediation-planning/` into your Claude skills directory
(e.g. `~/.claude/skills/`), or point your project at this repo. Claude will
invoke it when you ask to build or deploy a Tenable SC VM/remediation dashboard
or report, run the interview, generate the XML, validate it, and either hand you
the files or upload them with credentials you provide.

## Correctness

SC stores each `<definition>` as base64(PHP-serialized) with UTF-8 **byte**-length
prefixes, so these files must be generated, never hand-edited. `validate.py`
checks base64/round-trip integrity, invisible `fg==bg` colors, missing table
schedules, `sumip` host-count mistakes, and accidental Info-severity filters.
See [`references/sc-xml-format.md`](skills/vm-remediation-planning/references/sc-xml-format.md).

## License

MIT — see [LICENSE](LICENSE).
