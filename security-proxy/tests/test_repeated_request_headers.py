"""A header the client repeats is forwarded repeated, not collapsed to the last one.

O2's CcdbApi sends TWO If-None-Match headers on every cached read: the object's
ETag, then a second one carrying the timestamp (CcdbApi.cxx,
initCurlHTTPHeaderOptionsForRetrieve). Forwarding them through a dict kept only
the last, so CCDB never saw the ETag, never answered 304, and BasicCCDBManager
replaced its cached object on every get() -- testBasicCCDBManager.cxx:104/130/134
against the proxy, green against CCDB directly.

Measured, on one object, etag first and timestamp second as CcdbApi sends them:

    direct, etag only              304
    direct, etag + timestamp       304     <- CCDB honours the etag either way
    proxy,  etag only              304
    proxy,  etag + timestamp       303     <- the etag never arrived

The response path already forwards .raw for the same reason (test_header_case).
This is the request half of it.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import security_proxy as sp

from starlette.requests import Request

failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        failures.append(f"{label}: got {got!r}, want {want!r}")
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")


def pairs(headers):
    """(name, value) list, lowercased. Tolerates a plain dict so that a regressed
    build reports the collapse as a failure rather than an AttributeError."""
    if hasattr(headers, "raw"):
        return [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in headers.raw]
    return [(k.lower(), v) for k, v in headers.items()]


def values_of(headers, name):
    return [v for k, v in pairs(headers) if k == name]


def make_request(raw):
    """A Request carrying exactly `raw`, in order, duplicates included."""
    return Request({
        "type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "http", "path": "/ccdb/x", "query_string": b"",
        "server": ("127.0.0.1", 8080), "client": ("127.0.0.1", 1),
        "headers": raw,
    })


ETAG = b'"d21c9cef-fa59-11ec-9d70-0aa1229c1b9a"'
TIMESTAMP = b"1657000000000"


def run():
    failures.clear()
    route = sp.Route(prefix="/ccdb/", upstream="https://ccdb.invalid", token="t", name="ccdb")

    # --- the CcdbApi shape ----------------------------------------------------
    headers = sp.build_upstream_headers(make_request([
        (b"host", b"127.0.0.1:8080"),
        (b"authorization", b"Bearer gate-token"),
        (b"if-none-match", ETAG),
        (b"if-none-match", TIMESTAMP),
    ]), route)

    check("both If-None-Match values are forwarded, in the order sent",
          values_of(headers, "if-none-match"), [ETAG.decode(), TIMESTAMP.decode()])

    # --- what must still hold -------------------------------------------------
    check("the gate token is not forwarded upstream",
          values_of(headers, "authorization"), [])
    check("host is not forwarded upstream",
          values_of(headers, "host"), [])
    check("accept-encoding defaults to identity",
          values_of(headers, "accept-encoding"), ["identity"])

    # A client that sent one keeps one; the fix must not invent duplicates.
    single = sp.build_upstream_headers(make_request([
        (b"host", b"127.0.0.1:8080"),
        (b"if-none-match", ETAG),
    ]), route)
    check("a single If-None-Match stays single",
          values_of(single, "if-none-match"), [ETAG.decode()])

    # An ingest-injected header replaces whatever the client sent under that
    # name, including every copy of it -- it is a credential, not a list.
    injected = sp.Route(prefix="/x/", upstream="https://x.invalid", token="t", name="x",
                        ingest_headers={"X-Token": "slot"})
    sp.SLOTS["slot"] = "real-secret"
    try:
        out = sp.build_upstream_headers(make_request([
            (b"host", b"127.0.0.1:8080"),
            (b"x-token", b"client-a"),
            (b"x-token", b"client-b"),
        ]), injected)
        check("an injected header replaces every client copy",
              values_of(out, "x-token"), ["real-secret"])
    finally:
        sp.SLOTS.pop("slot", None)

    return list(failures)


if __name__ == "__main__":
    print(__doc__.splitlines()[0])
    bad = run()
    print(f"{'FAILED' if bad else 'passed'}: {len(bad)} failure(s)")
    sys.exit(1 if bad else 0)
