#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
list_scope.py -- list the repositories and asset groups available on a Tenable
Security Center console, so the user can pick IDs to filter a template by.

Standard library only (urllib + ssl); talks directly to the SC REST API with
API-key auth. Same credential handling as upload.py.

    GET /rest/repository?fields=id,name,type,dataFormat
    GET /rest/asset?fields=id,name,type    (SC "asset groups" == asset lists)

Credentials (never hard-code; pass via flags or environment):
    TSC_HOST         e.g. 10.0.0.5  or  sc.example.com
    TSC_PORT         default 443
    TSC_ACCESS_KEY
    TSC_SECRET_KEY

Examples:
    export TSC_HOST=sc.example.com TSC_ACCESS_KEY=... TSC_SECRET_KEY=...
    python3 list_scope.py --insecure                 # both, human tables
    python3 list_scope.py --repos                    # repositories only
    python3 list_scope.py --asset-groups             # asset groups only
    python3 list_scope.py --json                      # machine-readable

--insecure disables TLS verification (self-signed lab consoles only).
"""
import argparse
import json
import os
import ssl
import sys
import urllib.request


def _keyheader(access, secret):
    return "accesskey=%s; secretkey=%s" % (access, secret)


def _get(base, ctx, keyhdr, path):
    url = base + path
    req = urllib.request.Request(
        url, headers={"x-apikey": keyhdr, "Accept": "application/json"},
        method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        sys.exit("Connection failed: %s" % e.reason)


def _fetch(base, ctx, keyhdr, path, what):
    status, text = _get(base, ctx, keyhdr, path)
    if status != 200:
        sys.exit("Failed to list %s (HTTP %s): %s" % (what, status, text[:300]))
    try:
        rows = json.loads(text)["response"]
    except (ValueError, KeyError):
        sys.exit("Unexpected response listing %s: %s" % (what, text[:300]))
    # Repositories come back as a plain list. Assets come back wrapped as
    # {"usable": [...], "manageable": [...]} -- merge both, dedupe by id.
    if isinstance(rows, dict):
        merged, seen = [], set()
        for bucket in ("usable", "manageable"):
            for r in rows.get(bucket, []) or []:
                rid = str(r.get("id", ""))
                if rid not in seen:
                    seen.add(rid)
                    merged.append(r)
        rows = merged
    return rows


def list_repositories(base, ctx, keyhdr):
    rows = _fetch(base, ctx, keyhdr,
                  "/rest/repository?fields=id,name,type,dataFormat",
                  "repositories")
    out = []
    for r in rows:
        out.append({"id": str(r.get("id", "")), "name": r.get("name", ""),
                    "type": r.get("type", ""),
                    "dataFormat": r.get("dataFormat", "")})
    return out


def list_asset_groups(base, ctx, keyhdr):
    # In Tenable SC, "asset groups" are asset lists, served from /rest/asset.
    rows = _fetch(base, ctx, keyhdr, "/rest/asset?fields=id,name,type",
                  "asset groups")
    return [{"id": str(r.get("id", "")), "name": r.get("name", ""),
             "type": r.get("type", "")} for r in rows]


def _print_table(title, cols, rows):
    print("\n%s (%d)" % (title, len(rows)))
    if not rows:
        print("  (none)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    header = "  " + "  ".join(c.ljust(widths[c]) for c in cols)
    print(header)
    print("  " + "  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  " + "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repos", action="store_true",
                    help="list repositories only")
    ap.add_argument("--asset-groups", action="store_true",
                    help="list asset groups only")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of tables")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--access-key")
    ap.add_argument("--secret-key")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (self-signed lab consoles only)")
    args = ap.parse_args()

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

    # Default: show both.
    want_repos = args.repos or not (args.repos or args.asset_groups)
    want_groups = args.asset_groups or not (args.repos or args.asset_groups)

    result = {}
    if want_repos:
        result["repositories"] = list_repositories(base, ctx, keyhdr)
    if want_groups:
        result["asset_groups"] = list_asset_groups(base, ctx, keyhdr)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("Target: %s" % base)
    if want_repos:
        _print_table("Repositories", ["id", "name", "type", "dataFormat"],
                     result["repositories"])
    if want_groups:
        _print_table("Asset Groups (asset lists)", ["id", "name", "type"],
                     result["asset_groups"])
    print("\nUse these IDs in config.json: repository_ids / asset_group_ids.")


if __name__ == "__main__":
    main()
