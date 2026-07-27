#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Builds an importable Tenable Security Center REPORT XML (type=pdf) for the
"Vulnerability Management and Remediation Planning" template.

A report definition is a tree:
    definition = { chapters, coverPage, paper, tableOfContents, footer, header }
    chapter    -> { name, tag:"chapter", elements: { group, group, ... } }
    group      -> { name, tag:"group",   elements: { paragraph|component|iterator, ... } }
    paragraph  -> { name, tag:"paragraph", text, definition:None, location }
    component  -> { name, tag:"component", componentType, definition, location }
    iterator   -> { name, tag:"iterator", definition, location, elements: {components} }

Sections mirror the dashboard, plus a "Detailed Remediation" chapter that
iterates either by vulnerability or by host, per the user's choice.
"""
from sc_common import (b64, flt, C_NEUTRAL, C_GREEN, C_RED, C_AMBER, C_BLUE,
                       C_ORANGE, CRIT, HIGH, MED, LOW, SEV_LABEL)
from xml.sax.saxutils import escape

# Default SLA (days-to-remediate) per severity, used only if the user enabled
# SLAs but didn't override a given severity.
DEFAULT_SLA = {CRIT: 7, HIGH: 30, MED: 60, LOW: 90}

# VPR (Vulnerability Priority Rating) bands, high->low. Label carries the score
# range; value is the vprScore filter range. "0.1-10" = all VPR-scored (total).
VPR_BANDS = [("Critical (9.0-10.0)", "9-10"), ("High (7.0-8.9)", "7-8.9"),
             ("Medium (4.0-6.9)", "4-6.9"), ("Low (0.1-3.9)", "0.1-3.9")]
VPR_ALL = "0.1-10"

# The six Understanding-Risk columns (shared with the dashboard template).
RISK_COLUMNS = [
    "Total Assets (Hosts)", "Mitigated Vulns", "Unmitigated Vulns",
    "Exploitable", "Exploitable + Patch >30d", "Hosts w/ Exploitable Patch >30d",
]


def _risk_row_specs(gf, scope_filter, extra=None):
    """Six Understanding-Risk cells for one row (report context).

    Spec tuple: (tool, filters, colors, out_text, source).
    extra is an optional list of additional base filters applied to every cell
    in the row — e.g. the tracked-severity filter for the By-VPR matrix, so VPR
    bands still respect the user's severity selection.
    """
    base = [scope_filter] + list(extra or [])
    expl = base + [flt("exploitAvailable", "true")]
    expl_patch = expl + [flt("patchPublished", "30:all")]
    return [
        ("sumip", gf(base), C_BLUE, "ipCount", "cumulative"),
        ("sumid", gf(base), C_GREEN, "vulnCount", "patched"),   # mitigated
        ("sumid", gf(base), C_NEUTRAL, "vulnCount", "cumulative"),  # unmitigated
        ("sumid", gf(expl), C_AMBER, "vulnCount", "cumulative"),
        ("sumid", gf(expl_patch), C_ORANGE, "vulnCount", "cumulative"),
        ("sumip", gf(expl_patch), C_RED, "ipCount", "cumulative"),
    ]


def sla_days(cfg, sev_code):
    sla = cfg.get("sla") or {}
    return sla.get(SEV_LABEL[sev_code].lower(), DEFAULT_SLA.get(sev_code))


def detail_filters(cfg, gf):
    """Filters for the Detailed Remediation section (shared PDF chapter + CSV).

    Starts from the tracked severities under the global filter, then applies the
    same exploitable-only / critical-only scoping the user chose for the report.
    """
    sev_csv = ",".join(cfg["severities"])
    filters = gf([flt("severity", sev_csv)])
    if cfg.get("detail_exploitable_only"):
        filters = filters + [flt("exploitAvailable", "true")]
    if cfg.get("detail_critical_only"):
        filters = [f for f in filters if f["filterName"] != "severity"]
        filters = filters + [flt("severity", CRIT)]
    return filters

# ---------------------------------------------------------------------------
# location ids -- SC uses short, per-element opaque strings. They need only be
# present; we generate stable sequential ones.
# ---------------------------------------------------------------------------
_loc = [0xC0000]
def _next_loc():
    _loc[0] += 2
    return "c%x" % _loc[0]


# ---------------------------------------------------------------------------
# dataSource for report queries (context="report", styleID object form)
# ---------------------------------------------------------------------------
def _report_ds(tool, filters, sort_col="", sort_dir="", source="cumulative"):
    ds = {
        "querySourceID": "", "querySourceView": "", "querySourceType": source,
    }
    if sort_col:
        ds["sortColumn"] = sort_col
        ds["sortDirection"] = sort_dir
    ds["styleID"] = {"id": -2, "name": "", "description": "", "context": "",
                     "status": None, "createdTime": None, "modifiedTime": None}
    ds["query"] = {
        "name": "", "description": "", "tool": tool, "type": "vuln", "tags": "",
        "context": "report", "browseColumns": "", "browseSortColumn": "",
        "browseSortDirection": "ASC", "ownerGID": "0", "targetGID": "-1",
        "filters": {str(i): f for i, f in enumerate(filters)}, "groups": {},
    }
    return ds


# ---------------------------------------------------------------------------
# element builders
# ---------------------------------------------------------------------------
def paragraph(name, text):
    return {"name": name, "tag": "paragraph", "text": text,
            "definition": None, "location": _next_loc()}


def component(name, comp_type, definition):
    return {"name": name, "tag": "component", "componentType": comp_type,
            "definition": definition, "location": _next_loc()}


def table_component(name, columns, tool, filters, data_points=10,
                    sort_col="score", sort_dir="desc", source="cumulative"):
    defn = {
        "dataPoints": data_points, "displayDataPoints": str(data_points),
        "columns": {str(i): {"name": c} for i, c in enumerate(columns)},
        "dataSource": _report_ds(tool, filters, sort_col, sort_dir, source),
    }
    return component(name, "table", defn)


# A report matrix cell's dataSource is a SIMPLE 6-key map -- NOT the dashboard
# datasource. It carries no styleID / iteratorID / resultStyle / top-level
# context, and querySourceView is "" (empty), not "all". This is the exact
# shape used by Tenable's own shipped report matrices ("Track Mitigation
# Progress"); anything richer renders the matrix with header-only, no values.
_MATRIX_TS = 1750000000        # fixed timestamp component of query names
_matrix_id = [22]              # per-matrix component id, mirrors reference "23"
def _next_matrix_id():
    _matrix_id[0] += 1
    return _matrix_id[0]


def _matrix_query_name(comp_id, seq, base=False):
    # _<ts>.0.<serial>_matrix[_base]_<compId>_<seq>_1_1_1
    kind = "matrix_base" if base else "matrix"
    serial = comp_id * 100000 + seq * (2 if base else 1)
    return "_%d.0.%d_%s_%d_%d_1_1_1" % (_MATRIX_TS, serial, kind, comp_id, seq)


def _matrix_ds(tool, filters, source, comp_id, seq, base=False):
    return {
        "querySourceType": source, "querySourceID": "", "querySourceView": "",
        "sortColumn": "", "sortDirection": "",
        "query": {
            "name": _matrix_query_name(comp_id, seq, base=base),
            "description": "", "tool": tool, "type": "vuln", "tags": "",
            "context": "report", "browseColumns": "", "browseSortColumn": "",
            "browseSortDirection": "ASC", "ownerGID": "0", "targetGID": "-1",
            "filters": {i: f for i, f in enumerate(filters)}, "groups": {},
        },
    }


def _report_cell(comp_id, seq, row, col, tool, filters, colors,
                 out_text="vulnCount", source="cumulative"):
    """One report-matrix cell, shaped exactly like Tenable's shipped reports.

    Integer row/column (1-based) + subtype + a simple dataSource; integer-keyed
    conditional ending in `order`. No id/dataID (the reference has none).
    """
    cell = {
        "row": row, "column": col, "subtype": source,
        "dataSource": _matrix_ds(tool, filters, source, comp_id, seq),
        "conditionals": {0: {
            "conditionalName": "default", "conditionalOperator": "=",
            "conditionalValue": "", "outputType": "textCount",
            "outputText": out_text, "outputColors": colors, "order": 1,
        }},
        "sequence": seq,
    }
    return cell


def report_matrix(name, row_labels, col_labels, cell_specs):
    """Report-context matrix component. cell_specs row-major:
    (tool, filters, colors[, out_text[, source]]).

    Emits the full component wrapper Tenable's own report matrices carry (a
    now-type schedule, ical per-row clusters, integer-keyed arrays) -- a bare
    {name,tag,componentType,definition} wrapper (fine for tables/charts) leaves
    a report matrix rendering header-only with no data.
    """
    rows, ncols = len(row_labels), len(col_labels)
    comp_id = _next_matrix_id()
    cells = {}
    for idx, spec in enumerate(cell_specs):
        seq = idx + 1
        row = idx // ncols + 1
        col = idx % ncols + 1
        out_text = spec[3] if len(spec) > 3 else "vulnCount"
        source = spec[4] if len(spec) > 4 else "cumulative"
        cells[idx] = _report_cell(comp_id, seq, row, col, spec[0], spec[1],
                                  spec[2], out_text=out_text, source=source)
    # With stripType="column" there is ONE cluster per COLUMN strip (not per
    # row): Tenable's shipped 4x5 matrix carries 5 clusters (strips 1..5). SC
    # rebuilds clusters per-column strip on Edit/Save; emitting one-per-row
    # nulls out strips -> "NOT NULL constraint failed: MatrixCluster.strips".
    # Clusters use a VALID ical schedule (matching the reference), NOT the
    # component-level "now" placeholder (whose "Invalid date" fails reparse).
    clusters = {i: {"schedule": {
                        "start": "TZID=America/New_York:20170927T005500",
                        "repeatRule": "FREQ=WEEKLY;INTERVAL=1;BYDAY=SA",
                        "type": "ical", "enabled": "true"},
                    "strips": i + 1} for i in range(ncols)}
    defn = {
        "rows": str(rows), "columns": str(ncols), "title": name,
        "stripType": "column", "cells": cells,
        "rowLabels":    {i: {"text": t} for i, t in enumerate(row_labels)},
        "columnLabels": {i: {"text": t} for i, t in enumerate(col_labels)},
        "clusters": clusters,
    }
    return {
        "name": name, "description": "", "context": "", "status": -1,
        "createdTime": 0, "modifiedTime": 0, "groups": {}, "type": "component",
        "column": 1, "order": "0", "running": False, "lastUpdatedTime": 0,
        "lastCompletedUpdateTime": 0,
        "schedule": {"start": "TZID=:Invalid dateInvalid date",
                     "repeatRule": "FREQ=NOW;INTERVAL=", "type": "now",
                     "enabled": "true"},
        "tag": "component", "location": _next_loc(),
        "componentType": "matrix", "definition": defn,
    }


def piechart_component(name, tool, filters, label_col="severity"):
    defn = {
        "dataPoints": "10", "displayDataPoints": "10",
        "columns": {"0": {"name": "count"}},
        "dataSource": _report_ds(tool, filters, sort_col="severity",
                                 sort_dir="desc"),
        "labelColumns": label_col,
    }
    return component(name, "pieChart", defn)


def linechart_component(name, lines, timeframe_days=90):
    line_defs = {}
    for i, (label, filters) in enumerate(lines):
        line_defs[str(i)] = {
            "columns": {"0": {"name": "total"}}, "axisNum": "1", "label": label,
            "dataSource": _report_ds("trend", filters, source="cumulative"),
        }
    defn = {"styleID": "-1", "startTime": "0", "endTime": "0",
            "timeFrame": "%dd" % timeframe_days, "lines": line_defs}
    return component(name, "lineChart", defn)


def iterator(name, iter_tool, iter_filters, child_components, data_points=25,
             columns=None, sort_col="score", sort_dir="desc"):
    """An iterator repeats its child components once per row of its data source."""
    cols = columns or ["ip", "dnsName", "score", "total"]
    defn = {
        "dataSource": _report_ds(iter_tool, iter_filters, sort_col, sort_dir),
        "columns": {str(i): {"name": c} for i, c in enumerate(cols)},
        "dataPoints": data_points,
    }
    return {"name": name, "tag": "iterator", "definition": defn,
            "location": _next_loc(),
            "elements": {i: c for i, c in enumerate(child_components)}}


def group(name, elements):
    return {"name": name, "tag": "group",
            "elements": {i: e for i, e in enumerate(elements)}}


def chapter(name, groups):
    return {"name": name, "tag": "chapter",
            "elements": {i: g for i, g in enumerate(groups)}}


# ---------------------------------------------------------------------------
# Report XML assembly
# ---------------------------------------------------------------------------
def _write_report_xml(filename, name, description, definition,
                      rtype="pdf", style_family="1"):
    p = ['<?xml version="1.0" encoding="UTF-8"?>', "<report>",
         "\t<scVersion>6.6.0</scVersion>",
         "\t<name>%s</name>" % escape(name),
         "\t<description>%s</description>" % escape(description),
         "\t<type>%s</type>" % rtype,
         "\t<styleFamily>%s</styleFamily>" % style_family,
         "\t<attributeSetID>-1</attributeSetID>",
         "\t<schedule>", "\t\t<type>template</type>",
         "\t\t<start></start>", "\t\t<repeatRule></repeatRule>",
         "\t</schedule>",
         "\t<definition>%s</definition>" % b64(definition),
         "</report>", ""]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(p))
    return filename


def write_report(filename, name, description, chapters):
    definition = {
        "chapters": {i: c for i, c in enumerate(chapters)},
        "coverPage": {}, "paper": {}, "tableOfContents": {},
        "footer": {}, "header": {},
    }
    return _write_report_xml(filename, name, description, definition,
                             rtype="pdf", style_family="1")


# ---------------------------------------------------------------------------
# CSV report -- a flat, filtered vulnerability export (type=csv, styleFamily=5).
# Definition is a single list-style vulndetails data source plus a column set;
# there are no chapters. Column set mirrors Tenable's shipped "Detailed
# Vulnerabilities List" so the export is analysis-ready.
# ---------------------------------------------------------------------------
CSV_COLUMNS = [
    "pluginID", "pluginName", "familyID", "severity", "ip", "protocol", "port",
    "exploitAvailable", "repositoryID", "dnsName", "netbiosName", "macAddress",
    "synopsis", "description", "solution", "seeAlso", "riskFactor", "vprScore",
    "epssScore", "baseScore", "cvssV3BaseScore", "cvssVector", "cvssV3Vector",
    "cpe", "cve", "bid", "xref", "firstSeen", "lastSeen", "vulnPubDate",
    "patchPubDate", "pluginPubDate", "pluginModDate", "exploitEase",
    "exploitFrameworks", "checkType", "version",
]


def write_csv_report(filename, name, description, filters,
                     sort_col="pluginID", sort_dir="desc"):
    definition = {
        "dataSource": {
            "querySourceType": "cumulative", "querySourceID": "",
            "querySourceView": "", "sortColumn": sort_col,
            "sortDirection": sort_dir, "iteratorID": "-1",
            "resultStyle": "list",
            "query": {
                "name": "", "description": "", "tool": "vulndetails",
                "type": "vuln", "tags": "", "context": "report",
                "browseColumns": "", "browseSortColumn": "",
                "browseSortDirection": "ASC", "ownerGID": "0",
                "targetGID": "-1",
                "filters": {i: f for i, f in enumerate(filters)}, "groups": {},
            },
        },
        "columns": {i: {"name": c} for i, c in enumerate(CSV_COLUMNS)},
        "dataPoints": "2147483647",
    }
    return _write_report_xml(filename, name, description, definition,
                             rtype="csv", style_family="5")


# ---------------------------------------------------------------------------
# Detailed-remediation column sets
# ---------------------------------------------------------------------------
# For the "by vulnerability" iterator: each vulnerability row expands into the
# hosts it affects (the vulnerability's own details would just restate the row).
_HOST_COLS = ["ip", "dnsName", "osCPE", "total", "score"]
# For the "by host" iterator: each host row expands into the remediations it
# needs (a full per-host vulnerability dump would just be noise).
_REMEDIATION_COLS = ["solution", "scorePctg", "total", "hostTotal"]


# ---------------------------------------------------------------------------
# Main build
# ---------------------------------------------------------------------------
def build_chapters(cfg, gf):
    sevs = cfg["severities"]
    sev_csv = ",".join(sevs)
    scope = cfg["scope_label"]
    # Report-only record counts (cap + display label; "All" for uncapped).
    rem_max = cfg.get("top_remediation_max", 10)
    rem_label = cfg.get("top_remediation_label", str(rem_max))
    hosts_max = cfg.get("top_hosts_max", 20)
    hosts_label = cfg.get("top_hosts_label", str(hosts_max))
    # "Top 20 ..." for a numeric count, but just "All ..." for the uncapped one.
    rem_title = ("All" if rem_label == "All" else "Top %s" % rem_label)
    hosts_title = ("All" if hosts_label == "All" else "Top %s" % hosts_label)
    chapters = []

    # ---- Chapter: About ---------------------------------------------------
    chapters.append(chapter("About This Report", [
        group("1.1", [
            paragraph("1.1.1",
                "This report supports Vulnerability Management and Remediation "
                "Planning. It summarizes vulnerability trends, scanning history, "
                "risk by asset group and severity, and prioritized remediation "
                "opportunities."),
            paragraph("1.1.2",
                "Scope for this report: %s. Informational (Info) findings are "
                "excluded, as they are scan metadata rather than "
                "vulnerabilities." % scope),
        ]),
    ]))

    # ---- Chapter: Vulnerability Overview ---------------------------------
    lines = [(SEV_LABEL[s], gf([flt("severity", s)])) for s in sevs]
    chapters.append(chapter("Vulnerability Overview", [
        group("2.1", [
            paragraph("2.1.1",
                "Vulnerability trend over time, one line per tracked severity."),
            linechart_component("Vulnerability Trend Over Time", lines),
        ]),
        group("2.2", [
            paragraph("2.2.1",
                "Current severity distribution of unmitigated findings."),
            piechart_component("Severity Distribution", "sumseverity",
                               gf([flt("severity", sev_csv)])),
        ]),
    ]))

    # ---- Chapter: SLA Compliance (only when SLAs are defined) ------------
    # Placed above Understanding Risk so SLA posture leads the risk sections.
    if cfg.get("sla"):
        row_labels, specs = [], []
        for s in sevs:
            days = sla_days(cfg, s)
            row_labels.append("%s (%d Days)" % (SEV_LABEL[s], days))
            base = [flt("severity", s)]
            specs.append(("sumid", gf(base), C_NEUTRAL))
            specs.append(("sumid", gf(base + [flt("firstSeen", "0:%d" % days)]),
                          C_GREEN))
            specs.append(("sumid", gf(base + [flt("firstSeen", "%d:all" % days)]),
                          C_RED))
        chapters.append(chapter("SLA Compliance", [
            group("2b.1", [
                paragraph("2b.1.1",
                    "Unmitigated findings measured against remediation SLAs. "
                    "'Within SLA' counts findings first seen inside the SLA "
                    "window; 'Overdue' counts findings older than it."),
                report_matrix("Vulnerability SLA Compliance", row_labels,
                              ["Total Unmitigated", "Within SLA", "Overdue"],
                              specs),
            ]),
        ]))

    # ---- Chapter: Understanding Risk -------------------------------------
    # Order: By Severity, By VPR, Top 10 Remediation, Top 20 Hosts.
    # By-Severity matrix rows: each tracked severity plus a grand-total row.
    sev_rows, sev_specs = [], []
    for s in sevs:
        sev_rows.append(SEV_LABEL[s])
        sev_specs.extend(_risk_row_specs(gf, flt("severity", s)))
    sev_rows.append("Total (All Tracked)")
    sev_specs.extend(_risk_row_specs(gf, flt("severity", sev_csv)))
    # By-VPR matrix rows: each VPR band plus a total row. Every band is still
    # scoped to the tracked severities (same as By-Severity), otherwise the
    # matrix would count severities the user excluded.
    sev_scope = [flt("severity", sev_csv)]
    vpr_rows, vpr_specs = [], []
    for label, vpr in VPR_BANDS:
        vpr_rows.append(label)
        vpr_specs.extend(_risk_row_specs(gf, flt("vprScore", vpr),
                                         extra=sev_scope))
    vpr_rows.append("Total (All VPR)")
    vpr_specs.extend(_risk_row_specs(gf, flt("vprScore", VPR_ALL),
                                     extra=sev_scope))
    chapters.append(chapter("Understanding Risk", [
        group("3.1", [
            paragraph("3.1.1",
                "Risk breakdown by CVSS severity: total hosts, mitigated vs "
                "unmitigated findings, exploitable exposure, and long-overdue "
                "(>30d patchable) exploitable exposure."),
            report_matrix("Understanding Risk - By Severity", sev_rows,
                          RISK_COLUMNS, sev_specs),
        ]),
        group("3.2", [
            paragraph("3.2.1",
                "Risk breakdown by Vulnerability Priority Rating (VPR) band. "
                "VPR is Tenable's threat-based priority score; unlike fixed "
                "CVSS severity, it reflects current exploitability and threat "
                "intelligence. Columns match the by-severity view."),
            report_matrix("Understanding Risk - By VPR", vpr_rows,
                          RISK_COLUMNS, vpr_specs),
        ]),
        group("3.3", [
            paragraph("3.3.1",
                "%s remediation opportunities ranked by risk reduction. "
                "Addressing these solutions removes the most risk per action."
                % ("All" if rem_label == "All" else "Top %s" % rem_label)),
            table_component("%s Remediation Opportunities" % rem_title,
                            ["solution", "scorePctg", "hostTotal", "total"],
                            "sumremediation", gf([flt("severity", sev_csv)]),
                            data_points=rem_max, sort_col="scorePctg",
                            sort_dir="desc"),
        ]),
        group("3.4", [
            paragraph("3.4.1",
                "Most vulnerable hosts (%s), ranked by weighted severity "
                "score." % ("all" if hosts_label == "All"
                            else "top %s" % hosts_label)),
            table_component("%s Most Vulnerable Hosts" % hosts_title,
                            ["ip", "dnsName", "osCPE", "total", "score",
                             "vulnBar"], "sumip",
                            gf([flt("severity", sev_csv)]),
                            data_points=hosts_max),
        ]),
    ]))

    # ---- Chapter: Detailed Remediation (grouping-dependent, optional) -----
    # Skipped entirely when the user opts out of the detailed section.
    if not cfg.get("detail_enabled", True):
        return chapters

    detail_max = cfg.get("detail_max", 50)
    detail_flt = detail_filters(cfg, gf)

    if cfg["group_remediation_by"] == "vulnerability":
        # One block per vulnerability: the hosts it affects + its full details.
        # Grouped by vulnerability, so the per-vulnerability detail table would
        # just restate the row itself — only the affected-hosts breakdown adds
        # information inside the loop.
        it = iterator(
            "Per-Vulnerability Detail", "sumid", detail_flt,
            child_components=[
                paragraph("4.2.2", "Hosts affected by this vulnerability:"),
                table_component("Affected Hosts", _HOST_COLS, "sumip",
                                detail_flt, data_points=100),
            ],
            data_points=detail_max,
            columns=["pluginID", "pluginName", "severity", "total",
                     "hostTotal"],
            sort_col="severity")
        chapters.append(chapter("Detailed Remediation (by Vulnerability)", [
            group("4.1", [
                paragraph("4.1.1",
                    "Vulnerabilities are listed by severity. Each vulnerability "
                    "expands into the hosts it affects and its remediation "
                    "details."),
            ]),
            group("4.2", [
                paragraph("4.2.1", "Per-vulnerability breakdown:"),
                it,
            ]),
        ]))
    else:  # group by host
        # Grouped by host, so a full per-host vulnerability dump is noise — the
        # remediations table already tells the operator what to fix on the host.
        it = iterator(
            "Per-Host Detail", "sumip", detail_flt,
            child_components=[
                paragraph("4.2.2", "Remediations needed on this host:"),
                table_component("Host Remediations", _REMEDIATION_COLS,
                                "sumremediation", detail_flt,
                                data_points=100, sort_col="scorePctg",
                                sort_dir="desc"),
            ],
            data_points=detail_max,
            columns=["ip", "dnsName", "osCPE", "total", "score"],
            sort_col="score")
        chapters.append(chapter("Detailed Remediation (by Host)", [
            group("4.1", [
                paragraph("4.1.1",
                    "Hosts are listed by weighted severity. Each host expands "
                    "into the remediations it needs and the vulnerabilities "
                    "present on it."),
            ]),
            group("4.2", [
                paragraph("4.2.1", "Per-host breakdown:"),
                it,
            ]),
        ]))

    return chapters
