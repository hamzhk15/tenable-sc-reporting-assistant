# Tenable SC XML format — hard-won rules

Everything Tenable SC stores inside a `<definition>` is
**base64(PHP-serialized)**. PHP serialization is byte-length prefixed
(`s:N:"..."`) where **N is the UTF-8 byte length, not the character count** —
so multibyte characters (`–`, `≤`, `→`, `£`) each count as several bytes.
**Hand-editing a definition silently breaks the length prefixes and the import
fails.** Always generate programmatically (`scripts/sc_common.py`), and always
run `scripts/validate.py` before delivering.

> **Golden rule for extending this skill:** never hand-author a `<definition>`.
> Compose the tested builders in `sc_dashboard.py` / `sc_report.py`, then
> validate. Every rule below was once a real import failure or a wrong render.

## Dashboard (`<dashboardTab>`, scVersion 6.2.0)

- Each `<component>` has `componentType` ∈ `matrix`, `table`, `lineChart`,
  `pieChart`.
- **Table components require a top-level `<schedule>FREQ=DAILY;INTERVAL=1</schedule>`**
  between `<order>` and `<definition>`. Matrix components embed the schedule
  inside each cluster instead.
- **`outputColors` is `foreground:background`** (NOT background:foreground).
  fg==bg gives invisible white-on-white cells. Proven palette:
  neutral `000000:ffffff`, green `ffffff:79ab3d`, red `ffffff:dd4b50`,
  amber `000000:f8c851`, blue `ffffff:2c87d6`, orange `000000:f18c43`.
- **Matrix cells:** `outputType=textCount`; `outputText` = `vulnCount` (default)
  or `ipCount`. **Every `sumip` host-count cell MUST set `outputText=ipCount`** —
  the builder defaults to `vulnCount`, so a `sumip` cell left at default
  silently shows the vuln count in a "Hosts" column.
- **lineChart:** `lines` is an array of series, each with a `dataSource` whose
  query `tool=trend` and `resultStyle=trend`, plus `timeFrame` like `90d`.
  Keep the trend window fixed (90d); tying it to `data_freshness` made the
  chart stop rendering.
- **Dashboards have no filter-description paragraph** (reports do). To keep the
  applied scope legible, the generator suffixes a compact **scope tag** to the
  dashboard name AND every component header, e.g.
  `[Active · 90d · Repo:1,2 · AG:3,9,14 · CHML]`
  (data source · freshness window · repos · asset-groups · severity initials).
  Built in `generate.py::normalize` as `cfg["scope_tag"]`; applied in
  `sc_dashboard.build_components`' `add()` helper.

### Matrix clusters — THE cluster-count rule (was a silent-render bug)

A matrix has `stripType` = `"column"` (this template) or `"row"`. SC clusters
the strips of that axis, and **the number of `clusters` must equal the count of
that axis:**

- `stripType="column"` → **one cluster per COLUMN** (`range(len(columnLabels))`).
- `stripType="row"` → one cluster per row.

Getting this wrong has two failure modes we hit:
1. **Dashboard:** too few clusters → the un-clustered columns are never queried,
   so the widget shows "No Data" until the user manually re-saves it (the
   "must edit every chart to make it render" symptom). Confirmed by diffing an
   SC-resaved export: SC's only substantive change was padding `clusters` out
   to the column count.
2. **Report:** too few clusters → `NOT NULL constraint failed:
   MatrixCluster.strips` on Edit/Save.

Each cluster: `{id, strips:<i+1 as int>, schedule}`. Dashboard schedule is the
simple `FREQ=DAILY;INTERVAL=1`. **`validate.py` now enforces this count** — it
flags any matrix whose cluster count ≠ column count (or row count for
`stripType="row"`).

## Report (`<report>`, type pdf, scVersion 6.6.0)

Definition tree:

```
definition = { chapters, coverPage, paper, tableOfContents, footer, header }
chapter   -> { name, tag:"chapter",  elements:{ group, ... } }
group     -> { name, tag:"group",    elements:{ paragraph|component|iterator, ... } }
paragraph -> { name, tag:"paragraph", text, definition:null, location }
component -> { name, tag:"component", componentType, definition, location }
iterator  -> { name, tag:"iterator",  definition, location, elements:{components} }
```

- `componentType` seen: `table`, `pieChart`, `lineChart`, `matrix`.
- Report query `dataSource` uses `context="report"`.
- An **iterator** repeats its child components once per row of its own data
  source (e.g. per host, or per vulnerability).
- `location` values are short opaque ids; they need only be present.
- The whole report is ONE `<definition>` (matrices are nested inside
  `chapters`), unlike dashboards where each component has its own `<definition>`.

### Report matrix cell structure (verified vs Tenable's "Track Mitigation Progress")

A report matrix cell is a SIMPLE map — do NOT copy the dashboard cell shape:

```
cell = { row:<int>, column:<int>, subtype:<sourceType>,
         dataSource:{ querySourceType, querySourceID:"", querySourceView:"",
                      sortColumn:"", sortDirection:"", query:{ name, tool,
                      type:"vuln", context:"report", filters:<int-keyed>,
                      groups:{} } },
         conditionals:{ 0:{ conditionalName:"default", conditionalOperator:"=",
                            conditionalValue:"", outputType:"textCount",
                            outputText:"vulnCount"|"ipCount", outputColors,
                            order:1 } },
         sequence:<int> }
```

- `dataSource` is a 6-key map — **no** `styleID`/`iteratorID`/`resultStyle`/
  top-level `context`; `querySourceView` is `""` (not `"all"`).
- All matrix arrays (`cells`, `rowLabels`, `columnLabels`, `clusters`,
  `conditionals`, `filters`) are **integer-keyed** in Python (`{0:…,1:…}`) so
  the serializer emits PHP `i:0`, not `s:1:"0"`.
- Matrix components need the FULL component wrapper (name, description, context,
  status:-1, createdTime:0, modifiedTime:0, groups:{}, type:"component",
  column:1, order:"0", running:False, …, componentType:"matrix", definition).
  Tables/charts use a bare `{name, tag, componentType, definition}` wrapper.
- Same cluster-count rule as dashboards (see above).

### Iterators — show only the complementary breakdown

Detailed-Remediation iterates **by vulnerability** (`sumid`) or **by host**
(`sumip`). Inside the loop, only include the *complementary* table — the one
that adds information the grouping key doesn't already carry:

- by **host** → **Host Remediations** only (a full per-host vuln dump is noise).
- by **vulnerability** → **Affected Hosts** only (the vuln's own details just
  restate the row).

"By remediation" (a `sumremediation` iterator) is **not supported** by SC as a
report iterator; map any such request to by-vulnerability.

## CSV report (`<report>`, type **csv**, styleFamily **5**)

A flat, analysis-ready vulnerability export. Built by
`sc_report.write_csv_report`; imports through the SAME `reportDefinition/import`
endpoint as the PDF (the XML's `type`/`styleFamily` drive the format).

```
definition = { dataSource:{ querySourceType:"cumulative", querySourceID:"",
                 querySourceView:"", sortColumn:"pluginID", sortDirection:"desc",
                 iteratorID:"-1", resultStyle:"list",
                 query:{ tool:"vulndetails", type:"vuln", context:"report",
                         filters, groups:{} } },
               columns:<int-keyed {name}>,   # ~37 vuln columns
               dataPoints:"2147483647" }      # effectively uncapped
```

No chapters. Reuse the SAME filters the user chose for the detailed-remediation
section (`sc_report.detail_filters`).

## Query vocabulary

**Valid query `type`:** `vuln, lce, ticket, user, alert, mobile, consec`.
`type` is a property of the query, not a filter. This template uses `vuln`.

**Tools:** `sumid` (vuln summary / counts), `sumip` (host summary — pair with
`ipCount`), `sumseverity` (severity distribution, for pie), `sumremediation`
(solutions ranked by risk reduction), `trend` (time series), `vulndetails`
(per-finding detail rows for tables/iterators/CSV).

**Common table/column names:** `ip, dnsName, netbiosName, osCPE, macAddress,
score, total, vulnBar, severity, severityCritical, severityHigh, solution,
scorePctg, hostTotal, pluginID, pluginName, exploitAvailable, cve, bid, xref,
port, synopsis, description, seeAlso, firstSeen, lastSeen, exploitFrameworks,
patchPublished, vprScore, epssScore, cvssV3BaseScore`.

**Useful filters:** `severity` (4=Crit,3=High,2=Med,1=Low,0=Info),
`pluginType` (`active`/`passive`/`compliance`), `pluginID`, `repositoryIDs`,
`assetID`, `exploitAvailable`, `patchPublished`, `firstSeen`, `lastSeen`,
`daysMitigated`, `mitigatedStatus`, `vprScore`, `cveID`, `solutionID`.
Windows are `start:end` in days, e.g. `0:30`, `30:all`.

**Band-matrix scoping — two DIFFERENT rules (both were bugs):**

- **By-Asset-Group** rows are *scopes*, not risk levels, so each cell MUST still
  carry the tracked-severity filter — otherwise it counts severities the user
  excluded. Pass it via `_risk_row_specs(..., extra=[flt("severity", sev_csv)])`.
- **By-VPR** is a *reclassification*, not a scope. It must show the SAME
  criticality levels the user selected, but read THROUGH the VPR score instead
  of CVSS severity. So it maps each selected level to its VPR band
  (Critical→9.0-10, High→7.0-8.9, Medium→4.0-6.9, Low→0.1-3.9), shows only the
  selected levels' bands, and filters on `vprScore` **ALONE** — do NOT also
  apply the CVSS `severity` filter. Combining the two scales double-classifies
  the data and is wrong. Built from the `VPR_BY_SEV` map + `vpr_total_range()`
  in both `sc_dashboard.py` and `sc_report.py`.

(Earlier this skill wrongly added the severity filter to By-VPR; that made a
"Low VPR" row appear even when Low severity was deselected, because a
CVSS-Critical finding can carry a low VPR. The fix: VPR replaces severity here,
it does not combine with it. By-Severity is inherently scoped — each row *is* a
severity — and needs neither treatment.)

**Scanning-history specifics:**
- *Assets scanned* = `sumip` filtered on `pluginID=19506` (Nessus Scan
  Information) with a `lastSeen` window, output `ipCount`.
- *Vulns detected (last observed)* = `sumid` with a `lastSeen` window.
- *Vulns mitigated* = `sumid` with a `daysMitigated` window, source `patched`.

## REST import (`scripts/upload.py`, stdlib only)

- Auth header: `x-apikey: accesskey=<a>; secretkey=<s>`.
- Import = two steps: `POST /rest/file/upload` (multipart, field **`Filedata`**)
  → returns a token → `POST /rest/dashboard/import` (needs `{name, filename,
  order}`) or `POST /rest/reportDefinition/import` (`{name, filename}`).
- **Both PDF and CSV reports import via `reportDefinition/import`** — the XML
  type/styleFamily drives the export format.
- `--host` must be BARE (no scheme/port); the script builds
  `https://<host>:<port>`. `--insecure` for self-signed lab consoles only.
- Delete: `DELETE /rest/reportDefinition/{id}` or `/rest/dashboard/{id}`.
- Reading back a component definition over REST returns it as PARSED JSON (not
  base64) — handy for verification.
- **First-load "No Data":** after import some widgets don't query until their
  definition is re-committed once (Edit → toggle a filter → Save). With the
  cluster-count rule respected this should not happen, but warn the user it's a
  known SC behavior, not a bad template.

## Rules that were each an import failure or wrong render

1. Table without `<schedule>` → stuck "loading".
2. `outputColors` reversed → invisible cells.
3. `sumip` cell defaulting to `vulnCount` → wrong "Hosts" numbers.
4. Multibyte char in a hand-edited definition → byte-prefix mismatch → reject.
5. Filtering severity `0` (Info) → reports scan noise as vulnerabilities.
6. Matrix clusters counted by rows not columns → "No Data" widgets
   (dashboard) / `MatrixCluster.strips` NOT NULL error (report).
7. Report matrix cell using the dashboard cell shape → matrices render empty.
8. By-Asset-Group matrix missing the severity filter → counts excluded
   severities. (By-VPR is the opposite: it must filter on vprScore ALONE and
   map selected levels to VPR bands — adding the severity filter double-scales.)

`validate.py` checks 1–3, 5, 6, plus base64/round-trip integrity. Rules 4, 7, 8
are structural — they can't happen while you build via the tested functions.
