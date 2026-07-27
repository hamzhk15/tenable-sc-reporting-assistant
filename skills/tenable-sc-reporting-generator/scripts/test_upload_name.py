#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_upload_name.py -- regression guard for upload.py's name_from_xml().

Stdlib only; run directly:  python3 test_upload_name.py

Guards the bug where the SC importer derived the display name from the XML
FILENAME, silently dropping the dashboard scope tag (which lives in <name>, not
the filename). name_from_xml() must return the definition's own <name>, decode
XML entities, and fall back to the filename stem only when <name> is absent.
"""
import os
import tempfile

import upload

FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _write(dirpath, filename, contents):
    path = os.path.join(dirpath, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(contents)
    return path


def main():
    with tempfile.TemporaryDirectory() as d:
        # 1. The scope tag in <name> survives (the actual regression).
        tagged = ("VM Remediation Planning: Vulnerability Management &amp; "
                  "Remediation Planning [Active · 90d · Repo:1,2 "
                  "· AG:3,9,14 · CHML]")
        p = _write(d, "VM Remediation Planning - Dashboard.xml",
                   '<?xml version="1.0"?><dashboardTab><name>%s</name>'
                   '<description>x</description></dashboardTab>' % tagged)
        got = upload.name_from_xml(p)
        check("[Active" in got and "AG:3,9,14" in got,
              "scope tag dropped from name: %r" % got)
        check("&amp;" not in got and "&" in got,
              "XML entities not decoded: %r" % got)
        check(got != os.path.splitext(os.path.basename(p))[0],
              "fell back to filename despite a present <name>")

        # 2. First <name> wins (the dashboard/report name, not a component's).
        p = _write(d, "d.xml",
                   '<dashboardTab><name>Top Level</name>'
                   '<component><name>Inner Widget</name></component>'
                   '</dashboardTab>')
        check(upload.name_from_xml(p) == "Top Level",
              "did not take the first (top-level) <name>")

        # 3. No <name> -> fall back to the filename stem.
        p = _write(d, "Fallback Report.xml", "<report><type>pdf</type></report>")
        check(upload.name_from_xml(p) == "Fallback Report",
              "missing <name> did not fall back to filename stem")

        # 4. Unreadable path -> filename stem, no exception.
        missing = os.path.join(d, "Nope.xml")
        check(upload.name_from_xml(missing) == "Nope",
              "unreadable path did not fall back cleanly")

    if FAILS:
        print("FAILED:")
        for m in FAILS:
            print("  ✗ %s" % m)
        raise SystemExit(1)
    print("  ✓ name_from_xml: all cases pass")


if __name__ == "__main__":
    main()
