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
iterates either by remediation solution or by host, per the user's choice.
"""
from sc_common import (b64, flt, C_NEUTRAL, C_GREEN, C_RED, CRIT, HIGH, MED,
                       LOW, SEV_LABEL)
from xml.sax.saxutils import escape

# Default SLA (days-to-remediate) per severity, used only if the user enabled
# SLAs but didn't override a given severity.
DEFAULT_SLA = {CRIT: 7, HIGH: 30, MED: 60, LOW: 90}


def sla_days(cfg, sev_code):
    sla = cfg.get("sla") or {}
    return sla.get(SEV_LABEL[sev_code].lower(), DEFAULT_SLA.get(sev_code))

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


def matrix_component(name, defn):
    return component(name, "matrix", defn)


def _report_cell(seq, tool, filters, colors, out_text="vulnCount",
                 source="cumulative"):
    # Report-context matrices (unlike dashboard ones) require an explicit
    # id/dataID on BOTH the cell and its conditional -- REST import otherwise
    # fails with "NOT NULL constraint failed: DataConditional.dataID". The
    # cell sequence is a stable, unique value that links the two.
    return {
        "id": str(seq), "dataID": str(seq),
        "sequence": str(seq),
        "dataSource": _report_ds(tool, filters, source=source),
        "baseDataSource": [],
        "conditionals": [{
            "id": str(seq), "dataID": str(seq),
            "conditionalName": "default", "conditionalOperator": "=",
            "conditionalValue": "", "outputType": "textCount",
            "outputColors": colors, "outputText": out_text,
        }],
    }


def report_matrix(name, row_labels, col_labels, cell_specs, base_cluster=2000):
    """Report-context matrix. cell_specs row-major: (tool, filters, colors)."""
    rows = len(row_labels)
    cells = []
    for seq, spec in enumerate(cell_specs, start=1):
        cells.append(_report_cell(seq, spec[0], spec[1], spec[2]))
    clusters = [{"id": str(base_cluster + i), "strips": str(i + 1),
                 "schedule": "FREQ=DAILY;INTERVAL=1"} for i in range(rows)]
    defn = {
        "styleID": "-1", "cells": cells, "rows": str(rows),
        "columns": str(len(col_labels)), "title": name, "stripType": "column",
        "rowLabels":    [{"sequence": str(i + 1), "text": t}
                         for i, t in enumerate(row_labels)],
        "columnLabels": [{"sequence": str(i + 1), "text": t}
                         for i, t in enumerate(col_labels)],
        "clusters": clusters,
    }
    return matrix_component(name, defn)


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
def write_report(filename, name, description, chapters):
    definition = {
        "chapters": {i: c for i, c in enumerate(chapters)},
        "coverPage": {}, "paper": {}, "tableOfContents": {},
        "footer": {}, "header": {},
    }
    p = ['<?xml version="1.0" encoding="UTF-8"?>', "<report>",
         "\t<scVersion>6.6.0</scVersion>",
         "\t<name>%s</name>" % escape(name),
         "\t<description>%s</description>" % escape(description),
         "\t<type>pdf</type>",
         "\t<styleFamily>1</styleFamily>",
         "\t<attributeSetID>-1</attributeSetID>",
         "\t<schedule>", "\t\t<type>template</type>",
         "\t\t<start></start>", "\t\t<repeatRule></repeatRule>",
         "\t</schedule>",
         "\t<definition>%s</definition>" % b64(definition),
         "</report>", ""]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(p))
    return filename


# ---------------------------------------------------------------------------
# Detailed-remediation column sets
# ---------------------------------------------------------------------------
# For the "by remediation" iterator: each solution row expands into its
# vulnerabilities and the hosts that need it.
_VULN_COLS = ["pluginID", "pluginName", "severity", "exploitAvailable",
              "cve", "patchPublished", "solution"]
_HOST_COLS = ["ip", "dnsName", "osCPE", "total", "score"]
# For the "by asset" iterator: each host row expands into its remediations
# and vulnerabilities.
_REMEDIATION_COLS = ["solution", "scorePctg", "total", "hostTotal"]


# ---------------------------------------------------------------------------
# Main build
# ---------------------------------------------------------------------------
def build_chapters(cfg, gf):
    sevs = cfg["severities"]
    sev_csv = ",".join(sevs)
    scope = cfg["scope_label"]
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

    # ---- Chapter: Understanding Risk (Top remediation opportunities) -----
    chapters.append(chapter("Understanding Risk", [
        group("3.1", [
            paragraph("3.1.1",
                "Top 10 remediation opportunities ranked by risk reduction. "
                "Addressing these solutions removes the most risk per action."),
            table_component("Top 10 Remediation Opportunities",
                            ["solution", "scorePctg", "hostTotal", "total"],
                            "sumremediation", gf([flt("severity", sev_csv)]),
                            data_points=10, sort_col="scorePctg",
                            sort_dir="desc"),
        ]),
        group("3.2", [
            paragraph("3.2.1",
                "Most vulnerable hosts, ranked by weighted severity score."),
            table_component("Top 20 Most Vulnerable Hosts",
                            ["ip", "dnsName", "osCPE", "total", "score",
                             "vulnBar"], "sumip",
                            gf([flt("severity", sev_csv)]), data_points=20),
        ]),
    ]))

    # ---- Chapter: SLA Compliance (only when SLAs are defined) ------------
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
            group("3b.1", [
                paragraph("3b.1.1",
                    "Unmitigated findings measured against remediation SLAs. "
                    "'Within SLA' counts findings first seen inside the SLA "
                    "window; 'Overdue' counts findings older than it."),
                report_matrix("Vulnerability SLA Compliance", row_labels,
                              ["Total Unmitigated", "Within SLA", "Overdue"],
                              specs),
            ]),
        ]))

    # ---- Chapter: Detailed Remediation (grouping-dependent) --------------
    detail_filters = gf([flt("severity", sev_csv)])
    if cfg.get("detail_exploitable_only"):
        detail_filters = detail_filters + [flt("exploitAvailable", "true")]
    if cfg.get("detail_critical_only"):
        detail_filters = [f for f in detail_filters if f["filterName"] != "severity"]
        detail_filters = detail_filters + [flt("severity", CRIT)]

    if cfg["group_remediation_by"] == "remediation":
        # One block per remediation solution: its vulns + hosts needing it.
        it = iterator(
            "Per-Remediation Detail", "sumremediation", detail_filters,
            child_components=[
                paragraph("4.2.2",
                    "Vulnerabilities addressed by this remediation:"),
                table_component("Related Vulnerabilities", _VULN_COLS,
                                "vulndetails", detail_filters, data_points=100,
                                sort_col="severity", sort_dir="desc"),
                paragraph("4.2.3", "Hosts that need this remediation:"),
                table_component("Affected Hosts", _HOST_COLS, "sumip",
                                detail_filters, data_points=100),
            ],
            data_points=cfg.get("detail_max", 50),
            columns=["solution", "scorePctg", "total", "hostTotal"],
            sort_col="scorePctg")
        chapters.append(chapter("Detailed Remediation (by Remediation)", [
            group("4.1", [
                paragraph("4.1.1",
                    "Remediations are listed by risk-reduction. Each remediation "
                    "expands into the vulnerabilities it fixes and the hosts that "
                    "need it."),
            ]),
            group("4.2", [
                paragraph("4.2.1", "Per-remediation breakdown:"),
                it,
            ]),
        ]))
    else:  # group by asset (host)
        it = iterator(
            "Per-Host Detail", "sumip", detail_filters,
            child_components=[
                paragraph("4.2.2", "Remediations needed on this host:"),
                table_component("Host Remediations", _REMEDIATION_COLS,
                                "sumremediation", detail_filters,
                                data_points=100, sort_col="scorePctg",
                                sort_dir="desc"),
                paragraph("4.2.3", "Vulnerabilities on this host:"),
                table_component("Host Vulnerabilities", _VULN_COLS,
                                "vulndetails", detail_filters, data_points=100,
                                sort_col="severity", sort_dir="desc"),
            ],
            data_points=cfg.get("detail_max", 25),
            columns=["ip", "dnsName", "osCPE", "total", "score"],
            sort_col="score")
        chapters.append(chapter("Detailed Remediation (by Asset)", [
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
