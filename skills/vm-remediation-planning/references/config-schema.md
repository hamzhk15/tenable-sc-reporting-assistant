# Config schema

`generate.py --config config.json` reads a single JSON object. All keys are
optional; defaults in **bold**.

| Key | Type | Values / default | Effect |
|-----|------|------------------|--------|
| `artifact` | string | `dashboard` \| `report` \| **`both`** | Which file(s) to produce. |
| `vuln_data` | string | **`active`** \| `all` | `active` adds `pluginType=active` to every query; `all` includes passive/other. |
| `data_freshness` | string | `day` \| `week` \| `month` \| `quarter` \| `year` \| **`all`** | Adds a global `lastSeen` window (`quarter`=90d, `year`=365d; skipped on cells that already key off `lastSeen`). |
| `severities` | array | subset of `critical,high,medium,low`; default **all four** | Severities tracked in every widget. **Info is always dropped.** |
| `sla` | object \| null | `{"critical":7,"high":30,"medium":60,"low":90}` | Remediation SLA days per severity. Embedded in descriptions; drives SLA labels. |
| `group_remediation_by` | string | **`vulnerability`** \| `host` | Report Detailed-Remediation chapter: iterate by vulnerability (each vuln → affected hosts + details) or by host (each host → its remediations + vulns). Grouping by remediation solution is not supported by SC. Legacy `findings`/`remediation`→`vulnerability`, `assets`→`host`. |
| `repository_ids` | array \| null | e.g. `[1,3]` | Adds global `repositoryIDs` filter. |
| `asset_group_ids` | array \| null | e.g. `[10,11]` | Adds `assetID` scoping. **2–10 groups** enables the By-Asset-Group matrix. |
| `asset_group_labels` | object | `{"10":"Servers"}` | Optional display names for the group rows. |
| `detail_enabled` | bool | **true** | Report only: include the Detailed Remediation chapter at all. `false` omits it. |
| `detail_max` | int \| `"all"` | **50** | Report only: records the Detailed iterator expands. `10`/`20`/`50`/`100` or `"all"` (uncapped). |
| `detail_exploitable_only` | bool | **false** | Report only: limit Detailed section to `exploitAvailable=true`. |
| `detail_critical_only` | bool | **false** | Report only: limit Detailed section to Critical. |
| `top_hosts_max` | int \| `"all"` | **20** | Report only: rows in "Most Vulnerable Hosts". `10`/`20`/`50`/`100` or `"all"`. |
| `top_remediation_max` | int \| `"all"` | **10** | Report only: rows in "Top Remediation Opportunities". `10`/`20`/`50`/`100` or `"all"`. |
| `title_prefix` | string | **`VM Remediation Planning`** | Filename + title prefix. |

## Example

```json
{
  "artifact": "both",
  "vuln_data": "active",
  "data_freshness": "month",
  "severities": ["critical", "high", "medium"],
  "sla": {"critical": 7, "high": 30, "medium": 60, "low": 90},
  "group_remediation_by": "vulnerability",
  "repository_ids": [1, 3],
  "asset_group_ids": [10, 11, 12],
  "asset_group_labels": {"10": "Servers", "11": "Workstations", "12": "DMZ"},
  "detail_enabled": true,
  "detail_max": 50,
  "detail_exploitable_only": true,
  "detail_critical_only": false,
  "top_hosts_max": 20,
  "top_remediation_max": 10,
  "title_prefix": "VM Remediation Planning"
}
```

Produces `VM Remediation Planning - Dashboard.xml` and
`VM Remediation Planning - Report.xml`.
