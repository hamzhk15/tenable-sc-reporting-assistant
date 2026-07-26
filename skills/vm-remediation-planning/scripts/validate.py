#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate.py -- pre-flight checks on a generated SC dashboard/report XML,
catching the failure classes that block import or render invisibly.

    python3 validate.py "VM Remediation Planning - Dashboard.xml" [more.xml ...]

Checks:
  * XML is well-formed.
  * Every <definition> is valid base64 and round-trips through the byte-
    accurate PHP (de)serializer with identical bytes (proves every s:N:
    length prefix is correct).
  * No matrix cell uses outputColors where foreground == background
    (invisible white-on-white).
  * Every dashboard <table> component carries a <schedule>.
  * No query filters on severity Info (0) -- Info is not a vulnerability.
  * Every sumip host-count cell sets outputText=ipCount (the classic
    "hosts column silently shows vuln count" bug).

Exit code 0 = all good, 1 = at least one problem.
"""
import base64
import re
import sys
import xml.etree.ElementTree as ET

from sc_common import ser, unser


def _check_definitions(raw, problems, label):
    for m in re.finditer(r"<definition>(.*?)</definition>", raw, re.S):
        blob = m.group(1).strip()
        if not blob:
            continue
        try:
            decoded = base64.b64decode(blob).decode("utf-8")
        except Exception as e:
            problems.append("%s: definition is not valid base64/utf-8 (%s)" % (label, e))
            continue
        try:
            obj = unser(decoded)
        except Exception as e:
            problems.append("%s: PHP-deserialize failed (%s)" % (label, e))
            continue
        # Round-trip: re-serialize and compare bytes -> proves length prefixes.
        if ser(obj) != decoded:
            problems.append("%s: PHP round-trip mismatch (byte-length prefix bug)" % label)
        _walk(obj, problems, label)


def _walk(obj, problems, label):
    """Recursively inspect a decoded definition object for content bugs."""
    if isinstance(obj, dict):
        # invisible-color check
        for cond in _iter_conditionals(obj):
            colors = cond.get("outputColors", "")
            if isinstance(colors, str) and ":" in colors:
                fg, bg = colors.split(":", 1)
                if fg == bg:
                    problems.append("%s: outputColors fg==bg (invisible cell): %s"
                                    % (label, colors))
        # sumip host-count bug + Info severity check
        q = None
        ds = obj.get("dataSource")
        if isinstance(ds, dict):
            q = ds.get("query")
        if isinstance(q, dict):
            tool = q.get("tool")
            filters = q.get("filters", {})
            fvals = filters.values() if isinstance(filters, dict) else filters
            for f in fvals:
                if isinstance(f, dict) and f.get("filterName") == "severity":
                    vals = str(f.get("value", "")).split(",")
                    if "0" in [v.strip() for v in vals]:
                        problems.append("%s: query filters Info severity (0) — "
                                        "Info is not a vulnerability" % label)
            # sumip cell defaulting to vulnCount
            if tool == "sumip":
                for cond in obj.get("conditionals", []):
                    if isinstance(cond, dict) and cond.get("outputText") == "vulnCount":
                        problems.append("%s: sumip cell with outputText=vulnCount "
                                        "(should be ipCount for host counts)" % label)
        for v in obj.values():
            _walk(v, problems, label)
    elif isinstance(obj, list):
        for v in obj:
            _walk(v, problems, label)


def _iter_conditionals(obj):
    conds = obj.get("conditionals")
    if isinstance(conds, list):
        for c in conds:
            if isinstance(c, dict):
                yield c


def _check_schedules(raw, problems, label):
    # Only applies to dashboards (table components need <schedule>).
    if "<dashboardTab>" not in raw:
        return
    for comp in re.findall(r"<component>(.*?)</component>", raw, re.S):
        ct = re.search(r"<componentType>(.*?)</componentType>", comp)
        if ct and ct.group(1) == "table" and "<schedule>" not in comp:
            problems.append("%s: table component missing <schedule>" % label)


def validate_file(path):
    problems = []
    try:
        raw = open(path, encoding="utf-8").read()
    except Exception as e:
        return ["%s: cannot read (%s)" % (path, e)]
    try:
        ET.fromstring(raw)
    except ET.ParseError as e:
        problems.append("%s: XML not well-formed (%s)" % (path, e))
        return problems
    _check_definitions(raw, problems, path)
    _check_schedules(raw, problems, path)
    return problems


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python3 validate.py FILE.xml [FILE.xml ...]")
    all_problems = []
    for path in sys.argv[1:]:
        probs = validate_file(path)
        if probs:
            all_problems.extend(probs)
            for p in probs:
                print("  ✗ %s" % p)
        else:
            print("  ✓ %s — OK" % path)
    if all_problems:
        print("\n%d problem(s) found." % len(all_problems))
        sys.exit(1)
    print("\nAll files valid.")


if __name__ == "__main__":
    main()
