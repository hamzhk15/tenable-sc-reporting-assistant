#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upload.py -- import a generated dashboard/report XML into a Tenable Security
Center console using API keys, via the pyTenable library.

    pip install pytenable

Tenable SC import is a two-step API flow that pyTenable exposes:
  1. POST the file to /file/upload            -> returns a server filename
  2. POST that filename to the import endpoint:
        dashboards -> /dashboard/import
        reports    -> /reportDefinition/import

Credentials (never hard-code; pass via flags or environment):
    TSC_HOST         e.g. 10.0.0.5  or  sc.example.com
    TSC_PORT         default 443
    TSC_ACCESS_KEY
    TSC_SECRET_KEY

Examples:
    export TSC_HOST=sc.example.com TSC_ACCESS_KEY=... TSC_SECRET_KEY=...
    python3 upload.py --dashboard "VM Remediation Planning - Dashboard.xml"
    python3 upload.py --report    "VM Remediation Planning - Report.xml"
    python3 upload.py --dashboard d.xml --report r.xml --name "Q3 VM Plan"

Use --insecure only for lab consoles with self-signed certificates.
"""
import argparse
import os
import sys


def _connect(args):
    try:
        from tenable.sc import TenableSC
    except ImportError:
        sys.exit("pyTenable is not installed. Run:  pip install pytenable")

    host = args.host or os.environ.get("TSC_HOST")
    access = args.access_key or os.environ.get("TSC_ACCESS_KEY")
    secret = args.secret_key or os.environ.get("TSC_SECRET_KEY")
    port = args.port or int(os.environ.get("TSC_PORT", "443"))
    if not (host and access and secret):
        sys.exit("Missing credentials. Provide --host/--access-key/--secret-key "
                 "or TSC_HOST / TSC_ACCESS_KEY / TSC_SECRET_KEY.")

    return TenableSC(host=host, port=port, access_key=access, secret_key=secret,
                     ssl_verify=not args.insecure)


def _import(sc, xml_path, endpoint, name=None):
    """Upload the XML then hit an import endpoint. Returns the API response."""
    if not os.path.isfile(xml_path):
        sys.exit("File not found: %s" % xml_path)

    # Step 1: upload the file; pyTenable returns the server-side filename token.
    with open(xml_path, "rb") as fh:
        filename = sc.files.upload(fh)

    # Step 2: reference it in the import call. SC accepts a "name" override and
    # requires the uploaded-file token under "filename".
    payload = {"filename": filename, "name": name or os.path.splitext(
        os.path.basename(xml_path))[0]}
    # pyTenable exposes the raw authenticated session via sc.post().
    resp = sc.post(endpoint, json=payload)
    try:
        return resp.json()
    except Exception:
        return {"status": getattr(resp, "status_code", "?"),
                "text": getattr(resp, "text", "")}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dashboard", help="dashboard XML to import")
    ap.add_argument("--report", help="report XML to import")
    ap.add_argument("--name", help="optional display name override")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--access-key")
    ap.add_argument("--secret-key")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (lab/self-signed only)")
    args = ap.parse_args()

    if not (args.dashboard or args.report):
        ap.error("provide --dashboard and/or --report")

    sc = _connect(args)
    print("Connected to Tenable SC.")

    if args.dashboard:
        r = _import(sc, args.dashboard, "dashboard/import", args.name)
        print("  ✓ dashboard imported:", r)
    if args.report:
        r = _import(sc, args.report, "reportDefinition/import", args.name)
        print("  ✓ report imported:", r)


if __name__ == "__main__":
    main()
