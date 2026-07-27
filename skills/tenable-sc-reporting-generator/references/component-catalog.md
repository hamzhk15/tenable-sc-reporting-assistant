# Component catalog — known-good building blocks

This catalog is the backbone of **freeform mode** (see SKILL.md). When a user
describes a dashboard or report in their own words, map the request to the
recipes below, propose the component list for confirmation, then build **only**
by calling these tested builders. **Never hand-author a `<definition>`.** Every
recipe here has shipped and passed `validate.py`; anything outside it is a new
builder that must be written, validated, and added here — not improvised inline.

All builders live in `scripts/sc_dashboard.py` (dashboard) and
`scripts/sc_report.py` (report/CSV). Filters are `flt(name, value)` from
`sc_common`. The **global-filter injector** `gf` (from `generate.make_gf(cfg)`)
adds `pluginType=active`, `repositoryIDs`, and the `lastSeen` freshness window
to a cell's base filters — always pass a cell's base filters through `gf`.

---

## Dashboard recipes (`sc_dashboard.py`)

Assemble a list of component dicts via the `add(name, desc, kind, col, defn)`
helper inside `build_components`, then `write_dashboard(...)`. `col` is 1 or 2
(two-column layout). The scope tag is appended to names automatically.

| Recipe | Builder call | Produces |
|--------|-------------|----------|
| **Trend line chart** | `linechart(lines)` where `lines=[(label, gf([flt("severity", s)])), …]` | One series per severity over 90d (window fixed — see format ref). |
| **Time-window matrix** | `matrix(title, row_labels, [w[0] for w in WINDOWS], specs)` | Rows × Last Day/Week/Month/Quarter/Year. Used for Scanning History. |
| **Understanding-Risk matrix** | `matrix(title, row_labels, RISK_COLUMNS, specs)` with `specs=_risk_row_specs(gf, scope_filter[, extra])` per row | 6 columns: Total Hosts, Mitigated, Unmitigated, Exploitable, Exploitable+Patch>30d, Hosts w/ that. Rows can be severity, VPR band, or asset group. |
| **Top-N table** | `table(columns, tool, gf(filters), data_points=N, sort_col, sort_dir)` | Ranked rows, e.g. top remediations (`sumremediation`), hosts (`sumip`), plugins. |
| **Pie / distribution** | (report has `piechart_component`; dashboard pie via `matrix`/`table` today) | Severity distribution. |

**Row scoping for Understanding-Risk matrices** (`_risk_row_specs(gf, scope_filter, extra=None)`):
- by **severity** → `scope_filter=flt("severity", code)`, no `extra`.
- by **VPR band** → `scope_filter=flt("vprScore", band)`, **`extra=[flt("severity", sev_csv)]`** (MUST carry severity — see format ref rule 8).
- by **asset group** → `scope_filter=flt("assetID", gid)`, optionally `extra` severity.
- **total row** → same as the others with a CSV of all tracked values.

**Cluster count is handled by `matrix()`** (one per column) — do not touch it.

---

## Report recipes (`sc_report.py`)

A report is `chapters` → `groups` → elements. Build elements, wrap in
`group(name, elements)`, wrap groups in `chapter(name, groups)`, collect a
`chapters` list, then `write_report(...)`.

| Recipe | Builder call | Produces |
|--------|-------------|----------|
| **Paragraph** | `paragraph(name, text)` | Narrative text (use this to describe applied filters — reports support it). |
| **Table** | `table_component(name, columns, tool, gf(filters), data_points, sort_col, sort_dir)` | A table element. |
| **Pie** | `piechart_component(name, tool, gf(filters), label_col)` | Distribution chart. |
| **Line chart** | `linechart_component(name, lines, timeframe_days)` | Trend chart. |
| **Matrix** | `report_matrix(name, row_labels, col_labels, cell_specs)` | Report-context matrix (uses the simple cell shape + column-count clusters automatically). |
| **Understanding-Risk matrix** | `report_matrix(title, rows, RISK_COLUMNS, specs)` with `specs=_risk_row_specs(gf, scope_filter[, extra])` | Same 6 columns as the dashboard; same severity-scoping rule. |
| **Iterator** | `iterator(name, iter_tool, iter_filters, child_components, data_points, columns, sort_col)` | Repeats children per row. `iter_tool="sumid"` → per vulnerability; `"sumip"` → per host. |

**Iterator children** — include only the *complementary* breakdown:
- per **host** (`sumip`) → one `table_component("Host Remediations", _REMEDIATION_COLS, "sumremediation", …)`.
- per **vulnerability** (`sumid`) → one `table_component("Affected Hosts", _HOST_COLS, "sumip", …)`.

---

## CSV report recipe (`sc_report.py`)

| Recipe | Builder call | Produces |
|--------|-------------|----------|
| **Flat vuln export** | `write_csv_report(filename, name, description, filters, sort_col, sort_dir)` | A `type=csv`/styleFamily 5 report over `CSV_COLUMNS` (~37 fields). Reuse `detail_filters(cfg, gf)` for the filter set. |

---

## Mapping user intent → recipes (freeform mode heuristics)

- "trend / over time / history" → **trend line chart** or **time-window matrix**.
- "by severity / by VPR / by asset group / breakdown" → **Understanding-Risk matrix**, rows chosen from the phrase (remember the VPR/asset-group severity-scoping rule).
- "top / worst / most … N" → **top-N table** (`sumremediation` for solutions, `sumip` for hosts, `sumid` for plugins/vulns).
- "SLA / overdue / within SLA" → SLA matrix (needs `cfg["sla"]`; rows per severity, columns Total/Within/Overdue).
- "per-host detail / per-vulnerability detail / remediation plan" → report **iterator**.
- "export / spreadsheet / CSV / raw list" → **CSV report**.
- "exploitable / has a patch / patch older than N days" → add `flt("exploitAvailable","true")` / `flt("patchPublished","N:all")` to the base filters.
- Any scope the user states (active-only, freshness, repos, asset groups, severities) → set it in `cfg` so `gf` applies it globally; it also drives the dashboard scope tag.

If a request needs a component **not** in this catalog, say so: propose the
closest catalog recipe, or flag that a new tested builder is required before it
can be delivered safely. Do not satisfy it by writing raw XML.
