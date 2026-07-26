#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upload.py -- import a generated dashboard/report XML into Tenable Security
Center using ONLY the Python standard library (no third-party packages, no pip).

Talks directly to the SC REST API with API-key auth:

  1. POST /rest/file/upload            (multipart)  -> {"response":{"filename": token}}
  2. POST /rest/dashboard/import       {"name","filename","order"}  (dashboards)
     POST /rest/reportDefinition/import{"name","filename"}          (reports)

Credentials (never hard-code; pass via flags or environment):
    TSC_HOST         e.g. 10.0.0.5  or  sc.example.com
    TSC_PORT         default 443
    TSC_ACCESS_KEY
    TSC_SECRET_KEY

Examples:
    export TSC_HOST=sc.example.com TSC_ACCESS_KEY=... TSC_SECRET_KEY=...
    python3 upload.py --dashboard "…- Dashboard.xml" --insecure
    python3 upload.py --report "…- Report.xml" --name "Q3 VM Plan"

--insecure disables TLS verification (self-signed lab consoles only).
"""
import argparse
import json
import os
import ssl
import sys
import urllib.request
import uuid


def _keyheader(access, secret):
    return "accesskey=%s; secretkey=%s" % (access, secret)


def _request(url, ctx, headers, data=None, method="POST"):
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        sys.exit("Connection failed: %s" % e.reason)


def _multipart(field_name, filename, content):
    """Encode one file field as multipart/form-data. Returns (body, content_type)."""
    boundary = "----vmplan%s" % uuid.uuid4().hex
    pre = ("--%s\r\n"
           'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
           "Content-Type: application/xml\r\n\r\n") % (boundary, field_name, filename)
    body = pre.encode("utf-8") + content + ("\r\n--%s--\r\n" % boundary).encode("utf-8")
    return body, "multipart/form-data; boundary=%s" % boundary


def upload_file(base, ctx, keyhdr, xml_path):
    with open(xml_path, "rb") as fh:
        content = fh.read()
    body, ctype = _multipart("Filedata", os.path.basename(xml_path), content)
    headers = {"x-apikey": keyhdr, "Content-Type": ctype,
               "Content-Length": str(len(body))}
    status, text = _request(base + "/rest/file/upload", ctx, headers, data=body)
    if status != 200:
        sys.exit("File upload failed (HTTP %s): %s" % (status, text[:400]))
    token = json.loads(text)["response"]["filename"]
    return token


def import_definition(base, ctx, keyhdr, endpoint, token, name, extra=None):
    body = {"filename": token, "name": name}
    if extra:
        body.update(extra)
    payload = json.dumps(body).encode("utf-8")
    headers = {"x-apikey": keyhdr, "Content-Type": "application/json",
               "Content-Length": str(len(payload))}
    status, text = _request(base + endpoint, ctx, headers, data=payload)
    if status != 200:
        sys.exit("Import failed (HTTP %s) at %s: %s" % (status, endpoint, text[:400]))
    return json.loads(text) if text.strip().startswith("{") else {"raw": text}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dashboard", help="dashboard XML to import")
    ap.add_argument("--report", help="report XML to import")
    ap.add_argument("--name", help="optional display-name override")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--access-key")
    ap.add_argument("--secret-key")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (self-signed lab consoles only)")
    args = ap.parse_args()

    if not (args.dashboard or args.report):
        ap.error("provide --dashboard and/or --report")

    host = args.host or os.environ.get("TSC_HOST")
    access = args.access_key or os.environ.get("TSC_ACCESS_KEY")
    secret = args.secret_key or os.environ.get("TSC_SECRET_KEY")
    port = args.port or int(os.environ.get("TSC_PORT", "443"))
    if not (host and access and secret):
        sys.exit("Missing credentials. Set TSC_HOST / TSC_ACCESS_KEY / "
                 "TSC_SECRET_KEY or pass --host/--access-key/--secret-key.")

    base = "https://%s:%d" % (host, port)
    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    keyhdr = _keyheader(access, secret)

    print("Target: %s" % base)
    if args.dashboard:
        tok = upload_file(base, ctx, keyhdr, args.dashboard)
        name = args.name or os.path.splitext(os.path.basename(args.dashboard))[0]
        # SC's dashboard/import requires an explicit tab position ('order').
        r = import_definition(base, ctx, keyhdr, "/rest/dashboard/import", tok,
                              name, extra={"order": 0})
        print("  ✓ dashboard imported:", json.dumps(r.get("response", r))[:200])
    if args.report:
        tok = upload_file(base, ctx, keyhdr, args.report)
        name = args.name or os.path.splitext(os.path.basename(args.report))[0]
        r = import_definition(base, ctx, keyhdr, "/rest/reportDefinition/import", tok, name)
        print("  ✓ report imported:", json.dumps(r.get("response", r))[:200])


if __name__ == "__main__":
    main()
