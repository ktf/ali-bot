"""Response header names are forwarded with the upstream's spelling, not lowercased.

Header names are case-insensitive only to clients that treat them so. O2's CcdbApi
stores them in a plain std::map keyed on the name exactly as received, and
BasicCCDBManager then looks up "ETag", "Valid-From", "Valid-Until" and
"Cache-Valid-Until" verbatim. Lowercase those and every lookup misses: the cache
never reports a hit, so each get() refetches -- and the refetch resets the cached
shared_ptr, freeing the object the caller is still holding. testCcdbApiHeaders
passed against CCDB directly and SEGFAULTED through the proxy for exactly this,
dereferencing a pointer that a "cache hit" had just freed.

Two layers lowercase independently, which is why this needs a test rather than
care: httpx lowercases its decoded `.items()` view, and Starlette lowercases again
in Response.init_headers. Only `httpx.Headers.raw` in and `raw_headers` out keeps
the original spelling.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import security_proxy as sp  # noqa: F401  (imported for consistency with the suite)

import httpx
from starlette.responses import Response

failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        failures.append(f"{label}: got {got!r}, want {want!r}")
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")


# The header names CcdbApi/BasicCCDBManager look up verbatim. If this list and
# the C++ ever disagree, the symptom is a silent cache miss, not an error.
CCDB_HEADERS = ["ETag", "Valid-From", "Valid-Until", "Cache-Valid-Until"]


def run():
    failures.clear()

    upstream = httpx.Headers([(n.encode(), b"1") for n in CCDB_HEADERS]
                             + [(b"Transfer-Encoding", b"chunked")])

    # --- the two layers that lose the spelling, documented by assertion --------
    check("httpx lowercases its decoded view",
          [k for k, _ in upstream.items()], [n.lower() for n in CCDB_HEADERS] + ["transfer-encoding"])
    check("starlette lowercases what it is handed as a dict",
          [k.decode() for k, _ in Response(headers={"Valid-From": "1"}).raw_headers
           if k != b"content-length"],
          ["valid-from"])

    # --- what the proxy must produce -----------------------------------------
    # Mirrors the forwarding loop: iterate .raw, drop hop-by-hop, keep the rest
    # byte-for-byte.
    excluded = {"transfer-encoding", "connection", "keep-alive"}
    forwarded = [(k, v) for k, v in upstream.raw
                 if k.decode("latin-1").lower() not in excluded]

    check("every CCDB header keeps its spelling",
          [k.decode() for k, _ in forwarded], CCDB_HEADERS)
    check("hop-by-hop headers are still dropped",
          any(k.decode().lower() == "transfer-encoding" for k, _ in forwarded), False)

    # raw_headers assigned after construction survives; headers= does not.
    resp = Response(content=b"")
    resp.raw_headers = list(forwarded)
    check("assigning raw_headers preserves case end to end",
          [k.decode() for k, _ in resp.raw_headers], CCDB_HEADERS)

    # --- repeated headers survive too, which a dict collapsed -----------------
    dupes = httpx.Headers([(b"Set-Cookie", b"a=1"), (b"Set-Cookie", b"b=2")])
    check("repeated headers are not collapsed", len(dupes.raw), 2)

    return list(failures)


if __name__ == "__main__":
    print(__doc__.splitlines()[0])
    bad = run()
    print(f"{'FAILED' if bad else 'passed'}: {len(bad)} failure(s)")
    sys.exit(1 if bad else 0)
