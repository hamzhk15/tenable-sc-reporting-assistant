#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate.py -- turn a config into importable Tenable Security Center XML for
the "Vulnerability Management and Remediation Planning" dashboard/report.

Two ways to provide config:

  1. Config file (recommended; Claude writes this from the interview):
       python3 generate.py --config config.json

  2. Interactive prompts (answers the same questions the skill asks):
       python3 generate.py --interactive

Outputs (into --out-dir, default current directory):
  * VM Remediation Planning - Dashboard.xml   (if artifact includes dashboard)
  * VM Remediation Planning - Report.xml       (if artifact includes report)

Config schema (all keys optional unless noted; sane defaults applied):
  {
    "artifact": "dashboard" | "report" | "both",   # default "both"
    "vuln_data": "active" | "all",                  # default "active"
    "data_freshness": "day"|"week"|"month"|"all",   # default "all"
    "severities": ["critical","high","medium","low"],  # tracked severities
    "sla": {"critical":7,"high":30,"medium":60,"low":90},  # or null
    "group_remediation_by": "assets" | "findings",  # default "findings"
    "repository_ids": [1,2] | null,
    "asset_group_ids": [10,11] | null,
    "asset_group_labels": {"10":"Servers"},          # optional display names
    "detail_exploitable_only": false,                # report only
    "detail_critical_only": false,                   # report only
    "title_prefix": "VM Remediation Planning"
  }
"""
import argparse
import json
import os
import sys

from sc_common import flt, CRIT, HIGH, MED, LOW, SEV_CODE, SEV_LABEL
import sc_dashboard
import sc_report

FRESHNESS_WINDOW = {"day": "0:1", "week": "0:7", "month": "0:30",
                    "quarter": "0:90", "all": None}
FRESHNESS_LABEL = {"day": "Last Day", "week": "Last Week",
                   "month": "Last Month", "quarter": "Last Quarter (90d)",
                   "all": "All data"}


# ---------------------------------------------------------------------------
# Config normalization
# ---------------------------------------------------------------------------
def normalize(raw):
    cfg = {}
    cfg["artifact"] = raw.get("artifact", "both").lower()
    cfg["vuln_data"] = raw.get("vuln_data", "active").lower()
    cfg["data_freshness"] = raw.get("data_freshness", "all").lower()

    # Severities -> ordered high->low list of numeric codes; drop Info always.
    sev_in = raw.get("severities") or ["critical", "high", "medium", "low"]
    order = [CRIT, HIGH, MED, LOW]
    codes = {SEV_CODE.get(str(s).lower(), str(s)) for s in sev_in}
    codes.discard("0")  # Info is never a vulnerability
    cfg["severities"] = [c for c in order if c in codes] or [CRIT, HIGH, MED, LOW]

    cfg["sla"] = raw.get("sla")  # dict or None
    grp = raw.get("group_remediation_by", "findings").lower()
    cfg["group_remediation_by"] = "remediation" if grp in ("findings", "remediation") else "asset"

    cfg["repository_ids"] = [str(r) for r in (raw.get("repository_ids") or [])] or None
    cfg["asset_group_ids"] = [str(a) for a in (raw.get("asset_group_ids") or [])] or None
    cfg["asset_group_labels"] = {str(k): v for k, v in (raw.get("asset_group_labels") or {}).items()}

    cfg["detail_exploitable_only"] = bool(raw.get("detail_exploitable_only", False))
    cfg["detail_critical_only"] = bool(raw.get("detail_critical_only", False))
    cfg["detail_max"] = int(raw.get("detail_max", 50))
    cfg["title_prefix"] = raw.get("title_prefix", "VM Remediation Planning")

    # Scope label (human-readable, embedded in component descriptions).
    parts = []
    parts.append("Active only" if cfg["vuln_data"] == "active" else "All vuln data")
    parts.append(FRESHNESS_LABEL[cfg["data_freshness"]]
                 if cfg["data_freshness"] in FRESHNESS_LABEL else "All data")
    if cfg["repository_ids"]:
        parts.append("Repos %s" % ",".join(cfg["repository_ids"]))
    if cfg["asset_group_ids"]:
        parts.append("Asset groups %s" % ",".join(cfg["asset_group_ids"]))
    parts.append("Severities " + "/".join(SEV_LABEL[s] for s in cfg["severities"]))
    cfg["scope_label"] = "; ".join(parts)
    return cfg


# ---------------------------------------------------------------------------
# Global-filter injector: applied to every widget's base filters.
#   * vuln_data=active -> pluginType=active
#   * data_freshness   -> lastSeen (skipped if the cell already uses lastSeen)
#   * repository_ids   -> repositoryIDs
# Info is excluded implicitly because no widget ever queries severity 0.
# ---------------------------------------------------------------------------
def make_gf(cfg):
    def gf(base_filters):
        out = list(base_filters)
        has_last_seen = any(f["filterName"] == "lastSeen" for f in out)
        if cfg["vuln_data"] == "active":
            if not any(f["filterName"] == "pluginType" for f in out):
                out.append(flt("pluginType", "active"))
        if cfg["repository_ids"]:
            out.append(flt("repositoryIDs", ",".join(cfg["repository_ids"])))
        win = FRESHNESS_WINDOW.get(cfg["data_freshness"])
        if win and not has_last_seen:
            out.append(flt("lastSeen", win))
        return out
    return gf


# ---------------------------------------------------------------------------
# Interactive interview (mirrors the questions in SKILL.md)
# ---------------------------------------------------------------------------
def _ask(prompt, default=""):
    try:
        v = input("%s%s: " % (prompt, " [%s]" % default if default else "")).strip()
    except EOFError:
        v = ""
    return v or default


def _ask_yn(prompt, default=False):
    d = "y" if default else "n"
    return _ask(prompt + " (y/n)", d).lower().startswith("y")


def interview():
    raw = {}
    print("=" * 64)
    print(" VM & Remediation Planning — Template Generator")
    print("=" * 64)
    raw["artifact"] = _ask("[1] Create dashboard / report / both", "both").lower()
    raw["vuln_data"] = _ask("[2] Vulnerability data: active / all", "active").lower()
    raw["data_freshness"] = _ask("[3] Data freshness: day / week / month / quarter / all", "all").lower()
    sev = _ask("[4] Severities to track (comma: critical,high,medium,low)",
               "critical,high,medium,low")
    raw["severities"] = [s.strip() for s in sev.split(",") if s.strip()]
    if _ask_yn("[5] Do you have SLAs defined?", False):
        raw["sla"] = {
            "critical": int(_ask("      Critical SLA days", "7")),
            "high": int(_ask("      High SLA days", "30")),
            "medium": int(_ask("      Medium SLA days", "60")),
            "low": int(_ask("      Low SLA days", "90")),
        }
    grp = _ask("[6] Group remediation by: assets / findings", "findings").lower()
    raw["group_remediation_by"] = grp
    repos = _ask("[7] Filter by repository IDs? comma-separated, or blank", "")
    raw["repository_ids"] = [r.strip() for r in repos.split(",") if r.strip()] or None
    ags = _ask("[8] Filter by asset group IDs? comma-separated, or blank", "")
    raw["asset_group_ids"] = [a.strip() for a in ags.split(",") if a.strip()] or None
    if raw["artifact"] in ("report", "both"):
        raw["detail_exploitable_only"] = _ask_yn(
            "[9] Detailed section: exploitable vulns only?", False)
        raw["detail_critical_only"] = _ask_yn(
            "[10] Detailed section: critical vulns only?", False)
    return raw


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
def generate(cfg, out_dir):
    gf = make_gf(cfg)
    written = []
    os.makedirs(out_dir, exist_ok=True)
    prefix = cfg["title_prefix"]

    if cfg["artifact"] in ("dashboard", "both"):
        comps = sc_dashboard.build_components(cfg, gf)
        fname = os.path.join(out_dir, "%s - Dashboard.xml" % prefix)
        sc_dashboard.write_dashboard(
            fname, "%s: Vulnerability Management & Remediation Planning" % prefix,
            "Vulnerability Management and Remediation Planning dashboard. "
            "Scope: %s." % cfg["scope_label"], comps)
        written.append((fname, len(comps), "dashboard"))

    if cfg["artifact"] in ("report", "both"):
        chaps = sc_report.build_chapters(cfg, gf)
        fname = os.path.join(out_dir, "%s - Report.xml" % prefix)
        sc_report.write_report(
            fname, "%s: Vulnerability Management & Remediation Planning" % prefix,
            "Vulnerability Management and Remediation Planning report. "
            "Scope: %s." % cfg["scope_label"], chaps)
        written.append((fname, len(chaps), "report"))

    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", help="path to config JSON")
    ap.add_argument("--interactive", action="store_true",
                    help="prompt for config instead of reading a file")
    ap.add_argument("--out-dir", default=".", help="output directory")
    args = ap.parse_args()

    if args.interactive:
        raw = interview()
    elif args.config:
        with open(args.config, encoding="utf-8") as f:
            raw = json.load(f)
    else:
        ap.error("provide --config FILE or --interactive")

    cfg = normalize(raw)
    written = generate(cfg, args.out_dir)

    print("\nScope: %s" % cfg["scope_label"])
    for fname, n, kind in written:
        unit = "components" if kind == "dashboard" else "chapters"
        print("  ✓ %-9s %2d %-11s -> %s" % (kind, n, unit, fname))
    print("\nImport in SC:")
    print("  Dashboard  -> Dashboard > Options > Add Dashboard > Import")
    print("  Report     -> Reporting > Report Templates > (Options) > Import")
    print("Or upload automatically with upload.py (see --help).")


if __name__ == "__main__":
    main()
