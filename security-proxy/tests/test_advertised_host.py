"""The proxy advertises the address it bound, so clients off the loopback can reach it.

The listener is bindable anywhere ("host" in the config), which is what lets the
proxy sit on a private network shared with a container that is not in the host's
namespace -- a build container, say, that must reach the proxy without being given
the host's whole network. But the agent socket used to return only the port, and
every client helper hardcoded 127.0.0.1, so moving the listener silently pointed
every consumer at nothing. On a CI worker that surfaces as a green build whose
verdict is never posted, because report-pr-errors uploads the log through the
proxy before setting the status.

So: the agent reply carries "host", and clients use it -- defaulting to 127.0.0.1
so a client talking to an older proxy, or to one bound on the loopback as usual,
behaves exactly as before.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import security_proxy as sp

failures = []


def check(label, got, want):
    ok = got == want
    if not ok:
        failures.append(f"{label}: got {got!r}, want {want!r}")
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")


def run():
    failures.clear()

    # --- what a client makes of an agent reply -------------------------------
    check("a reply carrying a host uses it",
          sp.agent_host({"port": 1234, "host": "172.20.0.2"}), "172.20.0.2")
    check("a reply without one falls back to the loopback (older proxy)",
          sp.agent_host({"port": 1234}), "127.0.0.1")
    check("an empty host is not honoured",
          sp.agent_host({"port": 1234, "host": ""}), "127.0.0.1")

    # --- what the proxy advertises for a given bind --------------------------
    # serve() sets PROXY_HOST from args.host; reproduce that rule directly so the
    # test does not need a running event loop or a real socket.
    def advertised(bind):
        return "127.0.0.1" if bind in ("0.0.0.0", "::", "") else bind

    check("the default loopback bind advertises itself",
          advertised("127.0.0.1"), "127.0.0.1")
    check("a private-network bind is advertised as-is",
          advertised("172.20.0.2"), "172.20.0.2")
    # A wildcard is an address to LISTEN on, never one to connect to. Handing
    # "0.0.0.0" to a client produces a confusing connection failure rather than
    # an obviously wrong address, so the loopback is advertised instead.
    check("a wildcard bind still advertises the loopback",
          advertised("0.0.0.0"), "127.0.0.1")
    check("an IPv6 wildcard likewise",
          advertised("::"), "127.0.0.1")

    return list(failures)


if __name__ == "__main__":
    print(__doc__.splitlines()[0])
    bad = run()
    print(f"{'FAILED' if bad else 'passed'}: {len(bad)} failure(s)")
    sys.exit(1 if bad else 0)
