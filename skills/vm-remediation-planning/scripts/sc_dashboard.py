#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Builds an importable Tenable Security Center DASHBOARD XML for the
"Vulnerability Management and Remediation Planning" template.

Components produced (subject to the user's config):
  * Vulnerability Trend Over Time            -> lineChart
  * Scanning History                         -> matrix
  * Understanding Risk - By Asset Group      -> matrix (2..10 groups)
  * Understanding Risk - By Severity         -> matrix
  * Understanding Risk - Remediation
    Opportunities (Top 10)                   -> table

All query constructs (tools, filters, output types, colors) are ones
proven to import and render in production SC dashboards.
"""
from sc_common import (b64, flt, C_NEUTRAL, C_GREEN, C_RED, C_AMBER, C_BLUE,
                       C_ORANGE, CRIT, HIGH, MED, LOW, SEV_LABEL)
from xml.sax.saxutils import escape

# Default SLA (days-to-remediate) per severity, used only if the user enabled
# SLAs but didn't override a given severity.
DEFAULT_SLA = {CRIT: 7, HIGH: 30, MED: 60, LOW: 90}


def sla_days(cfg, sev_code):
    """Days-to-remediate for a severity, from cfg['sla'] (keyed by name)."""
    sla = cfg.get("sla") or {}
    name = SEV_LABEL[sev_code].lower()
    return sla.get(name, DEFAULT_SLA.get(sev_code))

# Detection/mitigation windows used by the Scanning History matrix.
WINDOWS = [("Last Day", "0:1"), ("Last Week", "0:7"), ("Last Month", "0:30"),
           ("Last Quarter", "0:90"), ("Last Year", "0:365")]

# VPR (Vulnerability Priority Rating) bands, high->low. The label carries the
# score range; the value is the vprScore filter range. "0.1-10" is the union
# of all VPR-scored findings (used for the total row).
VPR_BANDS = [("Critical (9.0-10.0)", "9-10"), ("High (7.0-8.9)", "7-8.9"),
             ("Medium (4.0-6.9)", "4-6.9"), ("Low (0.1-3.9)", "0.1-3.9")]
VPR_ALL = "0.1-10"

# ---------------------------------------------------------------------------
# Query-name generation. SC names queries per-component; a simple stable
# counter keyed off the cell sequence avoids the "stuck loading" bug caused
# by unexpected names.
# ---------------------------------------------------------------------------
def _qname(seq):
    return "_1750000000.%04d_%d_1_1" % (seq, seq)


def datasource(tool, filters, source="cumulative", result="single",
               sort_col="", sort_dir="", qtype="vuln", qname=None,
               context="dashboard"):
    return {
        "querySourceType": source, "querySourceID": "", "querySourceView": "all",
        "sortColumn": sort_col, "sortDirection": sort_dir, "iteratorID": "-1",
        "context": context, "resultStyle": result,
        "query": {
            "name": qname if qname is not None else "_1750000000.0001_1_1_1",
            "description": "", "tool": tool, "type": qtype,
            "tags": "", "context": context, "browseColumns": "",
            "browseSortColumn": "", "browseSortDirection": "ASC",
            "ownerGID": "0", "targetGID": "-1", "filters": filters, "groups": [],
        },
    }


def cell(seq, tool, filters, colors, source="cumulative",
         out_text="vulnCount", qtype="vuln"):
    return {
        "sequence": str(seq),
        "dataSource": datasource(tool, filters, source=source, qtype=qtype,
                                 qname=_qname(seq)),
        "baseDataSource": [],
        "conditionals": [{
            "conditionalName": "default", "conditionalOperator": "=",
            "conditionalValue": "", "outputType": "textCount",
            "outputColors": colors, "outputText": out_text,
        }],
    }


def matrix(title, row_labels, col_labels, cell_specs, base_cluster=2000):
    """cell_specs is row-major: (tool, filters, colors[, source[, out_text[, qtype]]])."""
    rows = len(row_labels)
    cells = []
    for seq, spec in enumerate(cell_specs, start=1):
        tool, filters, colors = spec[0], spec[1], spec[2]
        source = spec[3] if len(spec) > 3 else "cumulative"
        out_text = spec[4] if len(spec) > 4 else "vulnCount"
        qtype = spec[5] if len(spec) > 5 else "vuln"
        cells.append(cell(seq, tool, filters, colors, source, out_text, qtype))
    clusters = [{"id": str(base_cluster + i), "strips": str(i + 1),
                 "schedule": "FREQ=DAILY;INTERVAL=1"} for i in range(rows)]
    return {
        "styleID": "-1", "cells": cells, "rows": str(rows),
        "columns": str(len(col_labels)), "title": title, "stripType": "column",
        "rowLabels":    [{"sequence": str(i + 1), "text": t}
                         for i, t in enumerate(row_labels)],
        "columnLabels": [{"sequence": str(i + 1), "text": t}
                         for i, t in enumerate(col_labels)],
        "clusters": clusters,
    }


def table(columns, tool, filters, data_points=10, sort_col="score",
          sort_dir="desc", source="cumulative"):
    return {
        "styleID": "-1", "columns": [{"name": c} for c in columns],
        "dataPoints": str(data_points), "displayDataPoints": str(data_points),
        "dataSource": datasource(tool, filters, source=source, result="list",
                                 sort_col=sort_col, sort_dir=sort_dir,
                                 qname="_1750000000.0001_table_1_1"),
    }


def linechart(lines, timeframe_days=90):
    """lines: list of (label, filters).  Each becomes a trended series."""
    line_defs = {}
    for i, (label, filters) in enumerate(lines):
        line_defs[str(i)] = {
            "columns": {"0": {"name": "total"}},
            "axisNum": "1", "label": label,
            "dataSource": datasource("trend", filters, result="trend",
                                     qname="_1750000000.%04d_lineChart_1_1" % (i + 1)),
        }
    return {
        "styleID": "-1", "startTime": "0", "endTime": "0",
        "timeFrame": "%dd" % timeframe_days, "lines": line_defs,
    }


# ---------------------------------------------------------------------------
# Dashboard XML assembly
# ---------------------------------------------------------------------------
def write_dashboard(filename, name, description, components, num_columns=2):
    p = ['<?xml version="1.0" encoding="UTF-8"?>', "<dashboardTab>",
         "\t<scVersion>6.2.0</scVersion>",
         "\t<name>%s</name>" % escape(name),
         "\t<description>%s</description>" % escape(description),
         "\t<numColumns>%d</numColumns>" % num_columns,
         "\t<columnWidths>"]
    width = 100 // num_columns
    for _ in range(num_columns):
        p.append("\t\t<column>%d</column>" % width)
    p += ["\t</columnWidths>", "\t<dashboardComponents>"]
    for c in components:
        p += ["\t\t<component>",
              "\t\t\t<name>%s</name>" % escape(c["name"]),
              "\t\t\t<description>%s</description>" % escape(c["desc"]),
              "\t\t\t<componentType>%s</componentType>" % c["kind"],
              "\t\t\t<type>%s</type>" % c["kind"],
              "\t\t\t<column>%d</column>" % c["column"],
              "\t\t\t<order>%d</order>" % c["order"]]
        # Non-matrix components (table, lineChart, pieChart) require a
        # top-level <schedule>; matrices embed the schedule per cluster.
        # The REST /dashboard/import validates this strictly (the UI import
        # is lenient), rejecting an empty/missing schedule as "Invalid
        # schedule type".
        if c["kind"] != "matrix":
            p.append("\t\t\t<schedule>FREQ=DAILY;INTERVAL=1</schedule>")
        p += ["\t\t\t<definition>%s</definition>" % b64(c["definition"]),
              "\t\t</component>"]
    p += ["\t</dashboardComponents>", "</dashboardTab>", ""]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(p))
    return filename


# ---------------------------------------------------------------------------
# The Understanding-Risk column set (shared by By-Asset-Group and By-Severity)
# ---------------------------------------------------------------------------
RISK_COLUMNS = [
    "Total Assets (Hosts)",
    "Mitigated Vulns",
    "Unmitigated Vulns",
    "Exploitable",
    "Exploitable + Patch >30d",
    "Hosts w/ Exploitable Patch >30d",
]


def _risk_row_specs(gf, scope_filter):
    """Build the 6 Understanding-Risk cells for one row.

    scope_filter is the filter that scopes the row (an asset-group filter or a
    severity filter), or None for a grand-total row.
    """
    base = [scope_filter] if scope_filter else []
    expl = base + [flt("exploitAvailable", "true")]
    expl_patch = expl + [flt("patchPublished", "30:all")]
    return [
        # 1. Total assets (hosts) -> sumip + ipCount
        ("sumip", gf(base), C_BLUE, "cumulative", "ipCount"),
        # 2. Mitigated vulns -> patched source
        ("sumid", gf(base), C_GREEN, "patched"),
        # 3. Unmitigated vulns -> cumulative
        ("sumid", gf(base), C_NEUTRAL),
        # 4. Exploitable
        ("sumid", gf(expl), C_AMBER),
        # 5. Exploitable with a patch available > 30 days
        ("sumid", gf(expl_patch), C_ORANGE),
        # 6. Hosts carrying an exploitable, >30d-patchable finding
        ("sumip", gf(expl_patch), C_RED, "cumulative", "ipCount"),
    ]


# ---------------------------------------------------------------------------
# Main build
# ---------------------------------------------------------------------------
def build_components(cfg, gf):
    """cfg: normalized config dict.  gf: global-filter injector (base -> list)."""
    C = []
    order_by_col = {1: 0, 2: 0}

    def add(name, desc, kind, col, defn):
        order_by_col[col] += 1
        C.append({"name": name, "desc": desc, "kind": kind, "column": col,
                  "order": order_by_col[col], "definition": defn})

    sevs = cfg["severities"]            # list of severity codes, high->low
    scope = cfg["scope_label"]

    # --- 1. Vulnerability Trend Over Time (lineChart) ----------------------
    # Trend window is fixed at 90 days (SC "Within 3 Months"). Tying it to
    # data_freshness caused the chart to stop rendering, so keep it constant.
    lines = [(SEV_LABEL[s], gf([flt("severity", s)])) for s in sevs]
    add("Vulnerability Trend Over Time",
        "Trend of unmitigated vulnerabilities over time, one line per tracked "
        "severity. Scope: %s." % scope,
        "lineChart", 1, linechart(lines))

    # --- 2. Scanning History (matrix) --------------------------------------
    # Row 1: assets scanned (plugin 19506, count HOSTS) per window.
    # Row 2: vulnerabilities detected (last observed) per window.
    # Row 3: vulnerabilities mitigated per window.
    sev_csv = ",".join(sevs)
    specs = []
    for _, win in WINDOWS:                          # assets scanned
        specs.append(("sumip", gf([flt("pluginID", "19506"),
                                    flt("lastSeen", win)]),
                      C_BLUE, "cumulative", "ipCount"))
    for _, win in WINDOWS:                          # vulns detected (last observed)
        specs.append(("sumid", gf([flt("severity", sev_csv),
                                    flt("lastSeen", win)]), C_AMBER))
    for _, win in WINDOWS:                           # vulns mitigated
        specs.append(("sumid", gf([flt("severity", sev_csv),
                                    flt("daysMitigated", win)]),
                      C_GREEN, "patched"))
    add("Scanning History",
        "Assets scanned (Plugin 19506), vulnerabilities detected (last "
        "observed), and vulnerabilities mitigated, across rolling windows. "
        "Scope: %s." % scope,
        "matrix", 1,
        matrix("Scanning History",
               ["Assets Scanned", "Vulns Detected (Last Observed)",
                "Vulns Mitigated"],
               [w[0] for w in WINDOWS], specs))

    # --- 3. Understanding Risk - By Asset Group (matrix) -------------------
    # Only when the user filtered by 2..10 asset groups.
    groups = cfg["asset_group_ids"]
    if groups and 2 <= len(groups) <= 10:
        row_labels, specs = [], []
        for gid in groups:
            row_labels.append(cfg["asset_group_labels"].get(gid, "Asset Group %s" % gid))
            specs.extend(_risk_row_specs(gf, flt("assetID", gid)))
        add("Understanding Risk - By Asset Group",
            "Per asset-group risk breakdown: total hosts, mitigated vs "
            "unmitigated findings, exploitable exposure, and long-overdue "
            "(>30d patchable) exploitable exposure. Scope: %s." % scope,
            "matrix", 2,
            matrix("Understanding Risk - By Asset Group",
                   row_labels, RISK_COLUMNS, specs))

    # --- 4. Understanding Risk - By Severity (matrix) ----------------------
    row_labels, specs = [], []
    for s in sevs:
        row_labels.append(SEV_LABEL[s])
        specs.extend(_risk_row_specs(gf, flt("severity", s)))
    # grand-total row across the tracked severities
    row_labels.append("Total (All Tracked)")
    specs.extend(_risk_row_specs(gf, flt("severity", sev_csv)))
    add("Understanding Risk - By Vulnerability Severity",
        "Per-severity risk breakdown (plus a total row): hosts, mitigated vs "
        "unmitigated findings, exploitable exposure, and long-overdue (>30d "
        "patchable) exploitable exposure. Scope: %s." % scope,
        "matrix", 2,
        matrix("Understanding Risk - By Severity",
               row_labels, RISK_COLUMNS, specs))

    # --- 4a. Understanding Risk - By VPR (matrix) --------------------------
    # Same six columns as By-Severity, but rows are VPR bands (threat-based
    # priority) instead of the fixed CVSS severity.
    row_labels, specs = [], []
    for label, vpr in VPR_BANDS:
        row_labels.append(label)
        specs.extend(_risk_row_specs(gf, flt("vprScore", vpr)))
    row_labels.append("Total (All VPR)")
    specs.extend(_risk_row_specs(gf, flt("vprScore", VPR_ALL)))
    add("Understanding Risk - By VPR",
        "Per-VPR-band risk breakdown (plus a total row): hosts, mitigated vs "
        "unmitigated findings, exploitable exposure, and long-overdue (>30d "
        "patchable) exploitable exposure. Rows use the Vulnerability Priority "
        "Rating (threat-based), not fixed CVSS severity. Scope: %s." % scope,
        "matrix", 2,
        matrix("Understanding Risk - By VPR",
               row_labels, RISK_COLUMNS, specs))

    # --- 4b. Vulnerability SLA Compliance (matrix) -------------------------
    # Only when the user defined SLAs. Per severity: unmitigated findings split
    # by age (firstSeen) against that severity's SLA -> Within SLA vs Overdue.
    if cfg.get("sla"):
        row_labels, specs = [], []
        for s in sevs:
            days = sla_days(cfg, s)
            row_labels.append("%s (%d Days)" % (SEV_LABEL[s], days))
            base = [flt("severity", s)]
            specs.append(("sumid", gf(base), C_NEUTRAL))
            # Within SLA: first seen within the SLA window (age 0..days).
            specs.append(("sumid", gf(base + [flt("firstSeen", "0:%d" % days)]),
                          C_GREEN))
            # Overdue: first seen older than the SLA window (age days..all).
            specs.append(("sumid", gf(base + [flt("firstSeen", "%d:all" % days)]),
                          C_RED))
        add("Vulnerability SLA Compliance",
            "Unmitigated findings per severity measured against remediation "
            "SLAs: total, within SLA (first seen within the SLA window), and "
            "overdue (older than the SLA window). Scope: %s." % scope,
            "matrix", 1,
            matrix("Vulnerability SLA Compliance",
                   row_labels,
                   ["Total Unmitigated", "Within SLA", "Overdue"], specs))

    # --- 5. Understanding Risk - Remediation Opportunities (table) ---------
    add("Understanding Risk - Remediation Opportunities (Top 10)",
        "Top 10 remediation opportunities ranked by risk reduction "
        "(Tenable-curated solutions). Scope: %s." % scope,
        "table", 1,
        table(["solution", "scorePctg", "hostTotal", "total"], "sumremediation",
              gf([flt("severity", sev_csv)]), data_points=10,
              sort_col="scorePctg", sort_dir="desc"))

    return C
