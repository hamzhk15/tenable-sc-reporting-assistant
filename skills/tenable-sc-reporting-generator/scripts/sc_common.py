#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared primitives for generating importable Tenable Security Center XML
(dashboards AND reports).

Everything Tenable SC stores inside a <definition> element is
base64(PHP-serialized). PHP serialization is byte-length prefixed
(s:N:"..."), where N is the UTF-8 BYTE length -- NOT the character
count. Multibyte characters (–, ≤, →, etc.) count as several bytes, so
these blobs MUST be generated programmatically; hand-editing silently
breaks the length prefixes and the import fails.

This module is deliberately dependency-free (stdlib only) so it can run
anywhere Python 3 is available.
"""
import base64
from xml.sax.saxutils import escape

# ---------------------------------------------------------------------------
# PHP serialization (byte-accurate, the exact dialect Tenable SC expects)
# ---------------------------------------------------------------------------
def ser(obj):
    """Serialize a Python object to a PHP-serialized string.

    Supports the subset SC uses: str, int, float, bool, None, dict, list.
    Lists are emitted as PHP arrays with sequential integer keys.
    """
    if obj is None:
        return "N;"
    if isinstance(obj, bool):
        return "b:%d;" % (1 if obj else 0)
    if isinstance(obj, int):
        return "i:%d;" % obj
    if isinstance(obj, float):
        return "d:%s;" % repr(obj)
    if isinstance(obj, str):
        return 's:%d:"%s";' % (len(obj.encode("utf-8")), obj)
    if isinstance(obj, dict):
        return "a:%d:{" % len(obj) + "".join(ser(k) + ser(v)
                                              for k, v in obj.items()) + "}"
    if isinstance(obj, list):
        return "a:%d:{" % len(obj) + "".join("i:%d;" % i + ser(v)
                                              for i, v in enumerate(obj)) + "}"
    raise TypeError("cannot serialize %r" % type(obj))


def unser(s):
    """Parse a PHP-serialized string (already decoded from UTF-8) to Python."""
    b = s.encode("utf-8")
    val, _ = _parse(b, 0)
    return val


def _parse(b, i):
    t = chr(b[i])
    if t == "N":                                   # N;
        return None, i + 2
    if t == "b":                                   # b:0;
        return b[i + 2] == ord("1"), i + 4
    if t == "i":                                   # i:123;
        j = b.index(b";", i)
        return int(b[i + 2:j]), j + 1
    if t == "d":                                   # d:1.5;
        j = b.index(b";", i)
        return float(b[i + 2:j]), j + 1
    if t == "s":                                   # s:len:"...";  (len in BYTES)
        j = b.index(b":", i + 2)
        n = int(b[i + 2:j])
        start = j + 2                              # skip :"
        raw = b[start:start + n]
        return raw.decode("utf-8"), start + n + 2  # skip closing ";
    if t == "a":                                   # a:count:{ k v k v ... }
        j = b.index(b":", i + 2)
        count = int(b[i + 2:j])
        k = j + 2                                  # skip :{
        out = {}
        for _ in range(count):
            key, k = _parse(b, k)
            val, k = _parse(b, k)
            out[key] = val
        return out, k + 1                          # skip }
    raise ValueError("bad PHP token %r at offset %d" % (t, i))


def b64(obj):
    """Serialize + base64-encode, ready to drop inside <definition>."""
    return base64.b64encode(ser(obj).encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Proven-rendering color palette.  Format is FOREGROUND:BACKGROUND
# (getting this backwards produces invisible white-on-white cells).
# ---------------------------------------------------------------------------
C_NEUTRAL = "000000:ffffff"   # black on white
C_GREEN   = "ffffff:79ab3d"   # good / within SLA / mitigated
C_RED     = "ffffff:dd4b50"   # bad / overdue / unmitigated
C_AMBER   = "000000:f8c851"   # warning
C_BLUE    = "ffffff:2c87d6"   # informational / hosts
C_PURPLE  = "ffffff:77619d"
C_ORANGE  = "000000:f18c43"   # escalation tier between amber and red

# ---------------------------------------------------------------------------
# Severity codes (Tenable SC internal numeric severities)
# ---------------------------------------------------------------------------
CRIT, HIGH, MED, LOW, INFO = "4", "3", "2", "1", "0"

SEV_LABEL = {CRIT: "Critical", HIGH: "High", MED: "Medium", LOW: "Low", INFO: "Info"}
SEV_CODE = {"critical": CRIT, "high": HIGH, "medium": MED, "low": LOW, "info": INFO}


# ---------------------------------------------------------------------------
# Filter helper
# ---------------------------------------------------------------------------
def flt(name, value, op="="):
    """Build a single query filter dict."""
    return {"filterName": name, "operator": op, "value": str(value)}
