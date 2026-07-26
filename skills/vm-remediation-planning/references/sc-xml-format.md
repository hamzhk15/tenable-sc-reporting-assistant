# Tenable SC XML format — hard-won rules

Everything Tenable SC stores inside a `<definition>` is
**base64(PHP-serialized)**. PHP serialization is byte-length prefixed
(`s:N:"..."`) where **N is the UTF-8 byte length, not the character count** —
so multibyte characters (`–`, `≤`, `→`, `£`) each count as several bytes.
**Hand-editing a definition silently breaks the length prefixes and the import
fails.** Always generate programmatically (`scripts/sc_common.py`).

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
- Report query `dataSource` uses `context="report"` and a `styleID` **object**
  (`{"id":-2,...}`), unlike dashboards which use `styleID:"-1"` string.
- An **iterator** repeats its child components once per row of its own data
  source (e.g. per host, or per remediation solution).
- `location` values are short opaque ids; they need only be present.

## Query vocabulary

**Valid query `type`:** `vuln, lce, ticket, user, alert, mobile, consec`.
`type` is a property of the query, not a filter. This template uses `vuln`.

**Tools:** `sumid` (vuln summary / counts), `sumip` (host summary — pair with
`ipCount`), `sumseverity` (severity distribution, for pie), `sumremediation`
(solutions ranked by risk reduction), `trend` (time series), `vulndetails`
(per-finding detail rows for tables/iterators).

**Common table/column names:** `ip, dnsName, netbiosName, osCPE, macAddress,
score, total, vulnBar, severity, severityCritical, severityHigh, solution,
scorePctg, hostTotal, pluginID, pluginName, exploitAvailable, cve, bid, xref,
port, synopsis, description, seeAlso, firstSeen, lastSeen, exploitFrameworks,
patchPublished`.

**Useful filters:** `severity` (4=Crit,3=High,2=Med,1=Low,0=Info),
`pluginType` (`active`/`passive`/`compliance`), `pluginID`, `repositoryIDs`,
`assetID`, `exploitAvailable`, `patchPublished`, `firstSeen`, `lastSeen`,
`daysMitigated`, `mitigatedStatus`, `vprScore`, `cveID`, `solutionID`.
Windows are `start:end` in days, e.g. `0:30`, `30:all`.

**Scanning-history specifics:**
- *Assets scanned* = `sumip` filtered on `pluginID=19506` (Nessus Scan
  Information) with a `lastSeen` window, output `ipCount`.
- *Vulns detected (last observed)* = `sumid` with a `lastSeen` window.
- *Vulns mitigated* = `sumid` with a `daysMitigated` window, source `patched`.

## Rules that were each an import failure

1. Table without `<schedule>` → stuck "loading".
2. `outputColors` reversed → invisible cells.
3. `sumip` cell defaulting to `vulnCount` → wrong "Hosts" numbers.
4. Multibyte char in a hand-edited definition → byte-prefix mismatch → reject.
5. Filtering severity `0` (Info) → reports scan noise as vulnerabilities.

Run `scripts/validate.py` — it checks all five plus base64/round-trip integrity.
