# Config schema

`generate.py --config config.json` reads a single JSON object. All keys are
optional; defaults in **bold**.

| Key | Type | Values / default | Effect |
|-----|------|------------------|--------|
| `artifact` | string | `dashboard` \| `report` \| **`both`** | Which file(s) to produce. |
| `vuln_data` | string | **`active`** \| `all` | `active` adds `pluginType=active` to every query; `all` includes passive/other. |
| `data_freshness` | string | `day` \| `week` \| `month` \| `quarter` \| **`all`** | Adds a global `lastSeen` window (`quarter`=90d; skipped on cells that already key off `lastSeen`). |
| `severities` | array | subset of `critical,high,medium,low`; default **all four** | Severities tracked in every widget. **Info is always dropped.** |
| `sla` | object \| null | `{"critical":7,"high":30,"medium":60,"low":90}` | Remediation SLA days per severity. Embedded in descriptions; drives SLA labels. |
| `group_remediation_by` | string | `assets` \| **`findings`** | Report Detailed-Remediation chapter: by host, or by remediation solution. (`findings` ≡ by remediation.) |
| `repository_ids` | array \| null | e.g. `[1,3]` | Adds global `repositoryIDs` filter. |
| `asset_group_ids` | array \| null | e.g. `[10,11]` | Adds `assetID` scoping. **2–10 groups** enables the By-Asset-Group matrix. |
| `asset_group_labels` | object | `{"10":"Servers"}` | Optional display names for the group rows. |
| `detail_exploitable_only` | bool | **false** | Report only: limit Detailed section to `exploitAvailable=true`. |
| `detail_critical_only` | bool | **false** | Report only: limit Detailed section to Critical. |
| `detail_max` | int | **50** | Max rows the Detailed iterator expands. |
| `title_prefix` | string | **`VM Remediation Planning`** | Filename + title prefix. |

## Example

```json
{
  "artifact": "both",
  "vuln_data": "active",
  "data_freshness": "month",
  "severities": ["critical", "high", "medium"],
  "sla": {"critical": 7, "high": 30, "medium": 60, "low": 90},
  "group_remediation_by": "findings",
  "repository_ids": [1, 3],
  "asset_group_ids": [10, 11, 12],
  "asset_group_labels": {"10": "Servers", "11": "Workstations", "12": "DMZ"},
  "detail_exploitable_only": true,
  "detail_critical_only": false,
  "title_prefix": "VM Remediation Planning"
}
```

Produces `VM Remediation Planning - Dashboard.xml` and
`VM Remediation Planning - Report.xml`.
