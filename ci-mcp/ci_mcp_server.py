#!/usr/bin/env python3

"""Diagnose the CI checkers: what the workers are doing, and why a build failed.

This exists because answering "why did that check go red?" by hand costs an
absurd amount of reading. A slc10 worker's stderr is a quarter of a million
lines; a single grep for "error" over one of them returned 657 KB, and one
aliBuild DEBUG line -- a package's full recipe, inlined -- is itself several
thousand characters. Nothing about that is hard, it is just enormous, and the
enormity is the whole problem.

So the rule every tool here follows is: NEVER RETURN RAW LOG. Fetch as much as
it takes, return a bounded, deduplicated summary. A tool that can emit an
unbounded blob is a tool that will one day emit a quarter of a million lines.

Read-only by construction. It resolves the read-only Nomad gate token and the
GitHub gate token from the security-proxy agent socket at call time -- the same
ones ~/.zsh-customizations/nomad.zsh exports -- and never the attended nomad-rw
slot. There is deliberately no way to dispatch, stop, or write a status from
here: those are decisions a human makes, and a diagnostic tool that can also
change the cluster is no longer a diagnostic tool.
"""

import json
import os
import os.path
import re
import subprocess
import sys

from collections import Counter, defaultdict

import requests

from mcp.server.fastmcp import FastMCP

AGENT_SOCKET = "/usr/local/var/run/security-proxy/agent/agent.sock"
ALIBOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# How much of a log to pull before giving up, and how much to ever hand back.
# The fetch cap is generous because the server can afford the bytes; the return
# caps are mean because the reader cannot.
MAX_FETCH_BYTES = 64 * 1024 * 1024
MAX_LINE_CHARS = 300
MAX_RETURN_LINES = 60

mcp = FastMCP("ci")


# ---------------------------------------------------------------------------
# Error patterns: imported, never copied.
#
# report-pr-errors has a well-tuned set of regexes -- compiler errors with and
# without ANSI colour, ninja and make failures, CMake, killed compilers, failed
# unit tests, full-system-test timeouts. Reproducing them here would mean two
# definitions of "what an error looks like" drifting apart, and the copy that
# loses is always the one nobody is reading when a new failure mode appears.
# The file has no .py extension, hence the loader dance.
# ---------------------------------------------------------------------------

#: Which of report-pr-errors' regexes to lift, and what to call each kind here.
#:
#: ORDER MATTERS: the first pattern to match wins, and ERRORS_RE is deliberately
#: broad -- it matches ": fatal error:", which is also how a compiler killed by
#: the OOM reaper announces itself ("c++: fatal error: Killed signal terminated
#: program cc1plus"). With the generic pattern first, KILLED_RE never fired and
#: an out-of-memory build was reported as an ordinary compile error, which is a
#: completely different diagnosis. So the specific kinds come first and the
#: catch-all comes last.
WANTED_PATTERNS = {
    "KILLED_RE": "killed",
    "CMAKE_ERROR_RE": "cmake",
    "FAILED_UNIT_TEST_RE": "test",
    "FST_TASK_TIMEOUT_RE": "fst-timeout",
    "FST_LOGFILE_RE": "fst-logfile",
    "FST_FAILED_CMD_RE": "fst-command",
    "ERRORS_RE": "error",
}


def _load_error_patterns():
    """Lift the `NAME_RE = re.compile("...")` assignments out of the source.

    Read rather than imported. Importing report-pr-errors means executing it,
    which pulls in alibot_helpers and its whole dependency tree -- so this
    server would need ali-bot installed in its venv just to learn what an error
    looks like, and would fall back to a worse pattern set the day that broke.

    Only string literals passed to re.compile are evaluated, and only for the
    names listed above, so this reads the file without running any of it.
    """
    import ast
    path = os.path.join(ALIBOT, "report-pr-errors")
    with open(path) as source:
        tree = ast.parse(source.read(), filename=path)
    found = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in WANTED_PATTERNS:
            continue
        call = node.value
        if not (isinstance(call, ast.Call) and call.args):
            continue
        try:
            found[WANTED_PATTERNS[target.id]] = re.compile(
                ast.literal_eval(call.args[0]))
        except (ValueError, re.error):
            continue          # a pattern we cannot read is one we skip, not a crash
    if "error" not in found:
        raise RuntimeError("ERRORS_RE not found in %s" % path)
    # Re-key in WANTED_PATTERNS order. `found` was filled in the order the
    # assignments appear in report-pr-errors, which puts the broad ERRORS_RE
    # first -- so without this the specific kinds are unreachable no matter how
    # this table is written.
    return {kind: found[kind] for kind in WANTED_PATTERNS.values()
            if kind in found}


try:
    PATTERNS = _load_error_patterns()
except Exception as err:                       # noqa: BLE001
    print("could not import report-pr-errors patterns: %s" % err, file=sys.stderr)
    PATTERNS = {"error": re.compile(r": (fatal )?error:|^ERROR: |ninja: build stopped")}


# ---------------------------------------------------------------------------
# Talking to the cluster, through the broker
# ---------------------------------------------------------------------------

def _gate(service):
    """(base_url, token) for a security-proxy route, resolved at call time.

    Both rotate -- the port is random per proxy start and the token rotates
    daily -- so nothing here may be cached across calls.
    """
    def ask(*args):
        return subprocess.run(
            ["security-proxy-token", "--socket", AGENT_SOCKET, *args],
            capture_output=True, text=True, check=True).stdout.strip()
    return ask("--addr"), ask(service)


def nomad_get(path, **params):
    addr, token = _gate("nomad")
    reply = requests.get(addr + path, params=params, timeout=60,
                         headers={"X-Nomad-Token": token})
    reply.raise_for_status()
    return reply.json()


def nomad_log(alloc_id, task, stream="stderr", max_bytes=MAX_FETCH_BYTES):
    """The tail of one task's log. Returns (text, truncated).

    origin=end means Nomad seeks backwards from the end, so a running build's
    most recent output costs one request rather than a stream of everything it
    has ever printed.

    `truncated` says the window filled up and older output was NOT read. It has
    to be reported: a claim worker writes hundreds of MB a day, so a failure
    from a few hours ago falls outside the default window, and a search that
    silently answers "no match" reads as "it never happened". That has produced
    confident wrong answers more than once.
    """
    addr, token = _gate("nomad")
    reply = requests.get(
        "%s/v1/client/fs/logs/%s" % (addr, alloc_id),
        params={"task": task, "type": stream, "plain": "true",
                "origin": "end", "offset": max_bytes, "follow": "false"},
        headers={"X-Nomad-Token": token}, timeout=300)
    reply.raise_for_status()
    text = reply.text
    truncated = len(reply.content) >= max_bytes - 65536
    if truncated:
        # The window opens mid-line; drop the fragment so a half-eaten
        # timestamp cannot parse as a real one.
        text = text.split("\n", 1)[-1]
    return text, truncated


#: aliBuild stamps the lines it emits itself with LOCAL time:
#:   2026-08-21@14:10:21:DEBUG:O2Suite:autotools:slc10_x86-64-...:
STAMP_RE = re.compile(r"^(\d{4}-\d\d-\d\d)@(\d\d:\d\d:\d\d):")


def line_time(line):
    """('2026-08-21', '14:10:21') for a stamped line, else None."""
    found = STAMP_RE.match(line)
    return (found.group(1), found.group(2)) if found else None


def parse_since(since, lines):
    """Normalise a `since` argument to a (date, time) pair, or None.

    Accepts "14:10", "14:10:21" or "2026-08-21@14:10". A bare time means today
    IN THE LOG'S OWN CLOCK -- the date of its newest stamped line, not this
    Mac's -- because the builders are on CEST and this machine need not be.
    """
    if not since:
        return None
    since = since.strip()
    date, _, clock = since.partition("@") if "@" in since else (None, "", since)
    parts = (clock.split(":") + ["00", "00"])[:3]
    clock = ":".join(part.zfill(2) for part in parts)
    if date is None:
        date = ""
        for raw in reversed(lines):
            stamp = line_time(raw)
            if stamp:
                date = stamp[0]
                break
    return (date, clock)


def window_from(lines, since):
    """Index of the first line at or after `since`.

    The log is chronological, so `since` selects a suffix and this is a scan for
    the boundary rather than a filter. Unstamped output -- raw compiler and
    shell text, which is most of a build log -- belongs to the last stamped line
    before it, so slicing at the boundary keeps it with the right round.
    """
    if since is None:
        return 0
    for index, raw in enumerate(lines):
        stamp = line_time(raw)
        if stamp and stamp >= since:
            return index
    return len(lines)


#: build-loop.sh prints one of these blocks per round, after merging the PR:
#:
#:   ci-round: check=build/O2/... pr=alisw/alidist#6193 head=09d34327...
#:   ci-round:   alidist=1a2b3c4d...
#:   ci-round:   O2=5e6f7a8b...
#:
#: It is the only thing in the log that says WHAT a stretch of output was
#: building. Everything else -- timestamps, PR numbers in passing, pinned SHAs
#: quoted by aliBuild -- has to be inferred, and inference has been wrong.
ROUND_RE = re.compile(r"^ci-round: check=(\S+) pr=(\S+) head=(\S+)")
ROUND_PKG_RE = re.compile(r"^ci-round:\s+(\S+)=(\S+)")


def find_rounds(lines):
    """[(index, check, pr, head, {pkg: sha}), ...] for the rounds in `lines`."""
    rounds = []
    for index, raw in enumerate(lines):
        head = ROUND_RE.match(raw)
        if head:
            rounds.append([index, head.group(1), head.group(2),
                           head.group(3), {}])
        elif rounds:
            pkg = ROUND_PKG_RE.match(raw)
            # Only while still in the block: a later ci-round: line starts a new
            # one, and anything else means the block has ended.
            if pkg and index == rounds[-1][0] + len(rounds[-1][4]) + 1:
                rounds[-1][4][pkg.group(1)] = pkg.group(2)
    return rounds


def describe_round(entry):
    _, check, pr, head, packages = entry
    parts = ["%s on %s@%.12s" % (check, pr, head)]
    parts += ["%s@%.12s" % item for item in sorted(packages.items())]
    return "; ".join(parts)


def log_span(lines):
    """What the window actually covers, dated. "" if nothing is stamped.

    The date is not decoration: a long-lived worker's log routinely spans
    midnight, and a bare "14:31:00 to 17:15:47" from yesterday is
    indistinguishable from the same clock times today. That has been read the
    wrong way round more than once.
    """
    first = last = None
    for raw in lines:
        stamp = line_time(raw)
        if stamp:
            first = first or stamp
            last = stamp
    if not first:
        return ""
    if first[0] == last[0]:
        return "%s %s to %s" % (first[0], first[1], last[1])
    return "%s %s to %s %s" % (first[0], first[1], last[0], last[1])


def scope_lines(lines, since, round_):
    """Slice a log to one round, or to a time. Returns (lines, start, label).

    `round_` wins over `since`: it is exact where a timestamp is a guess.
    """
    if round_:
        rounds = find_rounds(lines)
        if not rounds:
            return lines, 0, ("round=%s asked for, but no ci-round: banner is in "
                              "the window -- an old build-loop.sh, or the round "
                              "started further back than window_mb reaches"
                              % round_)
        if round_ == "last":
            picked = rounds[-1]
        else:
            try:
                picked = rounds[int(round_) - 1]
            except (ValueError, IndexError):
                return lines, 0, ("round=%s not found; %d round(s) in the window"
                                  % (round_, len(rounds)))
        return lines[picked[0]:], picked[0], "round: " + describe_round(picked)
    parsed = parse_since(since, lines)
    if parsed is None:
        return lines, 0, ""
    start = window_from(lines, parsed)
    return lines[start:], start, "since %s %s" % parsed


def window_note(lines, truncated, extra=""):
    """One line saying what was actually read, for every tool that reads a log.

    Without this the reader cannot tell "not in the log" from "not in the part
    of the log I looked at".
    """
    bits = []
    if extra:
        bits.append(extra)
    span = log_span(lines)
    if span:
        bits.append("covering %s" % span)
    if truncated:
        bits.append("WINDOW FULL -- older output not read; raise window_mb to "
                    "look further back")
    return "  [%s]" % "; ".join(bits) if bits else ""


def github_graphql(query, **variables):
    addr, token = _gate("github")
    reply = requests.post(addr + "/github/graphql", timeout=60,
                          headers={"Authorization": "Bearer " + token},
                          json={"query": query, "variables": variables})
    reply.raise_for_status()
    body = reply.json()
    if "errors" in body:
        raise RuntimeError(json.dumps(body["errors"])[:400])
    return body["data"]


#: Lines that match an error pattern but are not errors.
#:
#: Overwhelmingly the top of any ranking before this existed. aliBuild's
#: prefer_system_check compiles a probe for every optional dependency and prints
#: the compiler's complaint when it is absent -- "WARNING: GSL: <stdin>:1:10:
#: fatal error: gsl/gsl_version.h: No such file or directory". That failure is
#: the mechanism working: it is how aliBuild decides to build its own copy. It
#: says "fatal error" because the compiler said so, and it is prefixed WARNING
#: because aliBuild knows it is not one.
#:
#: The rule is deliberately about the WARNING prefix rather than about probes:
#: an error pattern matching inside a line its own author labelled a warning is
#: a false positive by construction, whatever produced it.
NOISE_RE = re.compile(
    r"^\s*WARNING:"                      # aliBuild's own downgrade, incl. probes
    r"|^\s*report-analytics:"            # telemetry helpers failing to report;
    r"|^\s*report-metric-monalisa:"      # every round, unrelated to the build
)

#: Errors that stop a build, as opposed to errors it survives. Used to rank, not
#: to filter -- a build that dies of one fatal error usually emits dozens of
#: incidental ones first, and frequency alone puts the noisy ones on top.
FATAL_RE = re.compile(
    r"ninja: build stopped:|make.*: \*\*\*|^\s*ERROR:|\[FATAL\]"
    r"|internal compiler error|fatal error: Killed signal")


def clip(line):
    line = line.rstrip("\n")
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " ...[clipped]"


#: How many following lines carry the message, per kind. A compiler puts its
#: complaint on the line that matched, so pulling context there is pure noise.
#: CMake does the opposite: "CMake Error at FetchContent.cmake:2106 (message):"
#: says only WHERE, and every word of WHY is on the lines beneath it -- reported
#: alone it is unactionable, which is exactly how it first came back here.
BODY_LINES = {"cmake": 6, "test": 1, "fst-command": 2}


def with_body(lines, position, kind):
    """The matched line plus the continuation lines that carry its meaning."""
    body = [strip_alibuild_prefix(lines[position])]
    for offset in range(1, BODY_LINES.get(kind, 0) + 1):
        if position + offset >= len(lines):
            break
        nxt = strip_alibuild_prefix(lines[position + offset]).strip()
        # CMake indents the body and separates paragraphs with blank lines; stop
        # at "Call Stack", which is location again rather than reason.
        if not nxt or nxt.startswith("Call Stack"):
            break
        body.append("      " + nxt)
    return "\n".join(body)


def strip_alibuild_prefix(line):
    """Drop aliBuild's "2026-08-19@21:17:45:DEBUG:O2:GEANT4:slc10_x86-64-...:".

    Two identical compiler errors from two packages are the same error; leaving
    the timestamp on makes every line unique and defeats deduplication.
    """
    return re.sub(r"^\d{4}-\d\d-\d\d@[\d:]+:[A-Z]+:[^:]*:[^:]*:[^:]*:\s*", "", line)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

#: Repos whose pending statuses name the worker building them. Used to answer
#: "which PR is this allocation on", which the logs cannot reliably say.
DEFAULT_REPOS = ("alisw/alidist", "AliceO2Group/AliceO2")


def building_now(repos):
    """Map allocation-id prefix -> (repo, PR, check), from pending statuses.

    The obvious approach -- scrape the log for the PR being built -- does not
    work: build-loop.sh prints that line once, at the start of a round, which by
    the time a build reaches [1300/4771] is hundreds of megabytes back. Reading
    that much log per worker to recover one number is absurd.

    But the worker already publishes the mapping. report_pr_errors --pending
    sets a status reading "Started <when> on <host_id>", and under Nomad
    host_id is the allocation id. So GitHub knows which allocation is building
    which PR, authoritatively, for one query per repo.
    """
    claims = {}
    for repo in repos:
        owner, _, name = repo.partition("/")
        try:
            data = github_graphql("""
            query($o:String!,$n:String!){repository(owner:$o,name:$n){
              pullRequests(states:OPEN,first:100,
                           orderBy:{field:UPDATED_AT,direction:DESC}){
                nodes{number commits(last:1){nodes{commit{status{contexts{
                  context state description}}}}}}}}}
            """, o=owner, n=name)
        except Exception:                       # noqa: BLE001
            continue
        for pull in data["repository"]["pullRequests"]["nodes"]:
            commits = pull["commits"]["nodes"]
            status = commits[0]["commit"]["status"] if commits else None
            for ctx in (status or {}).get("contexts", []):
                # Any state, not just PENDING. A first build says "Started ...
                # on <alloc>" and stays pending, but a REBUILD keeps its old
                # red or green and only rewrites the description to "Rechecking
                # since ... on <alloc>" -- so filtering on PENDING loses every
                # worker that is rebuilding, which is most of them once a queue
                # has drained. Stale descriptions naming a finished allocation
                # are harmless: they match no running one.
                match = re.search(r"\bon ([0-9a-f]{8})\b", ctx["description"] or "")
                if match:
                    claims[match.group(1)] = (repo, pull["number"], ctx["context"])
    return claims


@mcp.tool()
def ci_workers() -> str:
    """What every running CI checker allocation is doing right now.

    One line per worker: job, allocation, node, which check and PR it claimed,
    and how far into the build it is. Replaces the five-step dance of listing
    jobs, listing allocations, then grepping each log for the PR number and the
    ninja progress counter.
    """
    out = []
    claims = building_now(DEFAULT_REPOS)
    for job in nomad_get("/v1/jobs"):
        if not job["ID"].startswith("ci-"):
            continue
        for alloc in nomad_get("/v1/job/%s/allocations" % job["ID"]):
            if alloc["ClientStatus"] != "running":
                continue
            short = alloc["ID"][:8]
            line = ["%-16s %s on %s" % (job["ID"], short, alloc["NodeName"])]
            task = main_task(alloc)
            if task is None:
                out.append(line[0] + "  (no running task)")
                continue
            try:
                log, _ = nomad_log(alloc["ID"], task, max_bytes=2 * 1024 * 1024)
            except Exception as err:            # noqa: BLE001
                # Never echo the URL: it carries the broker's ephemeral port and
                # is noise in a summary line.
                out.append(line[0] + "  (no log for task %s: %s)"
                           % (task, type(err).__name__))
                continue
            # Identity from GitHub (authoritative), progress from the log tail
            # (which is where the recent output actually is).
            claim = claims.get(short)
            if claim:
                line.append("%s#%d %s" % (claim[0].split("/")[-1], claim[1],
                                          claim[2].rsplit("/", 1)[-1]))
            package = re.findall(r"DEBUG:[^:]*:([^:]+):(?:slc|osx)", log)
            progress = re.findall(r"\[(\d+)/(\d+)\]", log)
            if package:
                line.append("building %s" % package[-1])
            if progress:
                line.append("[%s/%s]" % progress[-1])
            out.append("  ".join(line))
    return "\n".join(out) or "no running ci-* allocations"


@mcp.tool()
def ci_build_errors(alloc: str, task: str = "ci", max_errors: int = 12,
                    since: str = "", round: str = "",
                    window_mb: int = 0) -> str:
    """Why this build failed: the distinct errors in its log, deduplicated.

    Applies ali-bot's own error patterns (the ones report-pr-errors uses to
    build the PR comment), strips aliBuild's per-line timestamp prefix so
    repeats collapse, and returns each distinct error once with a count. A
    build that fails 400 times for one reason reports one line, not 400.

    alloc may be a short id prefix, as with the nomad CLI.

    PASS `since` FOR A CLAIM-BASED WORKER. Those allocations are long-lived and
    their log holds many rounds for many PRs and several checks, so without it
    you get this round's failure next to an unrelated one from yesterday, with
    nothing to tell them apart. Take the check's "Started ..." time from its
    GitHub status -- that is UTC, the log is local -- and pass it as "HH:MM".

    `window_mb` overrides how far back to read (default 64). The reply always
    says what was covered and whether the window filled up.
    """
    alloc_id = _resolve_alloc(alloc)
    log, truncated = nomad_log(alloc_id, task,
                               max_bytes=(window_mb or 0) * 1024 * 1024
                               or MAX_FETCH_BYTES)
    hits = {}                     # key -> [count, sample, kind, last_position]
    kinds, skipped = Counter(), 0
    lines = log.splitlines()
    lines, start, scope_label = scope_lines(lines, since, round)
    # A full window only hides something if it could hide what was ASKED for.
    # start > 0 means the window already reaches back past the requested round
    # or time, so whatever fell off the front is older than what was asked for
    # -- warning about it just sends the reader re-fetching for nothing.
    if (since or round) and start > 0:
        truncated = False
    for position, raw in enumerate(lines):
        line = strip_alibuild_prefix(raw)
        if NOISE_RE.search(line):
            skipped += 1
            continue
        for kind, pattern in PATTERNS.items():
            if pattern.search(line):
                # Numbers vary between otherwise identical errors (line
                # numbers, template depths, addresses); collapse them so the
                # same failure in twenty files groups into one entry.
                key = (kind, re.sub(r"\d+", "#", line)[:MAX_LINE_CHARS])
                if key in hits:
                    hits[key][0] += 1
                    hits[key][3] = position
                else:
                    hits[key] = [1, with_body(lines, position, kind), kind,
                                 position]
                kinds[kind] += 1
                break
    if not hits:
        return ("no recognised errors in %s (%d lines scanned, %d suppressed as "
                "noise).%s\nThe build may have been killed rather than failed -- "
                "try ci_log_tail."
                % (alloc_id[:8], len(lines), skipped,
                   window_note(lines, truncated, scope_label)))

    def severity(entry):
        """Rank fatal-and-late above frequent.

        Sorting by count put ten copies of a harmless message above the two
        copies of the one that stopped the build -- and the decisive error is
        usually the LAST one, since everything after it is teardown. So: the
        kinds that are always serious first, then anything that looks
        build-stopping, then latest-first within each tier. Count is reported
        but never ranks.
        """
        count, sample, kind, position = entry
        if kind in ("killed", "cmake", "test", "fst-timeout",
                    "fst-logfile", "fst-command"):
            tier = 0
        elif FATAL_RE.search(sample):
            tier = 1
        else:
            tier = 2
        return (tier, -position)

    ranked = sorted(hits.values(), key=severity)
    head = "%d distinct error(s) in %s, %s" % (
        len(hits), alloc_id[:8],
        ", ".join("%s=%d" % kv for kv in kinds.most_common()))
    if skipped:
        head += " (%d noise lines suppressed)" % skipped
    head += window_note(lines, truncated, scope_label)
    out = [head]
    for count, sample, kind, _ in ranked[:max_errors]:
        body = "\n".join(clip(l) for l in sample.splitlines())
        out.append("  [%s%s] %s"
                   % (kind, " x%d" % count if count > 1 else "", body))
    if len(ranked) > max_errors:
        out.append("  ... and %d more distinct errors" % (len(ranked) - max_errors))
    return "\n".join(out)


@mcp.tool()
def ci_log_search(alloc: str, pattern: str, task: str = "ci",
                  max_matches: int = 20, since: str = "", round: str = "",
                  context: int = 0, oldest_first: bool = False,
                  window_mb: int = 0) -> str:
    """Search one allocation's log, returning counts and a capped sample.

    Deliberately not a grep: it reports how many lines matched and shows at
    most max_matches of them, clipped. Ask a broad question here without the
    answer arriving as several hundred kilobytes.

    Shows the LAST matches, not the first. On a claim-based worker the log
    spans many rounds and PRs, so the earliest matches are the stalest ones --
    reporting those as the current state has caused real mistakes. Pass
    oldest_first=True for the old behaviour, and prefer `since` (see
    ci_build_errors) to pin the round outright.

    `context` adds that many lines either side of each match, like grep -C:
    the fatal line is often a compiler warning cascade above a terse make
    error, and the match alone does not say which package was building.
    """
    alloc_id = _resolve_alloc(alloc)
    regex = re.compile(pattern)
    log, truncated = nomad_log(alloc_id, task,
                               max_bytes=(window_mb or 0) * 1024 * 1024
                               or MAX_FETCH_BYTES)
    lines = log.splitlines()
    lines, start, scope_label = scope_lines(lines, since, round)
    # A full window only hides something if it could hide what was ASKED for.
    # start > 0 means the window already reaches back past the requested round
    # or time, so whatever fell off the front is older than what was asked for
    # -- warning about it just sends the reader re-fetching for nothing.
    if (since or round) and start > 0:
        truncated = False
    positions = [index for index, raw in enumerate(lines) if regex.search(raw)]
    if not positions:
        return ("no match for %r in %s%s"
                % (pattern, alloc_id[:8], window_note(lines, truncated, scope_label)))

    cap = min(max_matches, MAX_RETURN_LINES)
    shown = positions[:cap] if oldest_first else positions[-cap:]
    head = "%d line(s) match %r in %s" % (len(positions), pattern, alloc_id[:8])
    if len(positions) > len(shown):
        head += " (showing %s %d)" % ("first" if oldest_first else "last",
                                      len(shown))
    head += window_note(lines, truncated, scope_label)

    out, previous_end = [head], None
    for position in shown:
        start, end = max(0, position - context), min(len(lines),
                                                     position + context + 1)
        # Only worth separating blocks when there are blocks: at context=0 every
        # non-adjacent match would get a rule, which is noise.
        if context and previous_end is not None and start > previous_end:
            out.append("  --")
        for index in range(max(start, previous_end or 0), end):
            marker = "  " if index == position else "   "
            out.append(marker + clip(strip_alibuild_prefix(lines[index])))
        previous_end = end
    return "\n".join(out)


@mcp.tool()
def ci_rounds(alloc: str, task: str = "ci", window_mb: int = 0) -> str:
    """What this worker has actually been building, round by round.

    Reads the `ci-round:` banners build-loop.sh prints after merging each PR:
    the check, the PR and head sha it claimed, and the resolved commit of every
    checkout including alidist. Package pins live inside alidist, so the alidist
    commit answers "was my recipe fix in this build?" without fetching anything.

    Use this BEFORE ci_build_errors on a claim-based worker: the round number it
    prints can be passed straight back as `round`, which beats guessing a
    `since` timestamp from a GitHub status in another timezone.
    """
    alloc_id = _resolve_alloc(alloc)
    log, truncated = nomad_log(alloc_id, task,
                               max_bytes=(window_mb or 0) * 1024 * 1024
                               or MAX_FETCH_BYTES)
    lines = log.splitlines()
    rounds = find_rounds(lines)
    if not rounds:
        return ("no ci-round: banner in %s%s\nEither the worker predates the "
                "banner in build-loop.sh, or every round in the window started "
                "before it -- try a larger window_mb."
                % (alloc_id[:8], window_note(lines, truncated)))
    out = ["%d round(s) in %s%s"
           % (len(rounds), alloc_id[:8], window_note(lines, truncated))]
    for number, entry in enumerate(rounds, start=1):
        stamp = ""
        for raw in lines[entry[0]:entry[0] + 8]:
            found = line_time(raw)
            if found:
                stamp = found[1] + " "
                break
        out.append("  [round=%d] %s%s" % (number, stamp, describe_round(entry)))
    return "\n".join(out)


@mcp.tool()
def ci_log_tail(alloc: str, task: str = "ci", lines: int = 30) -> str:
    """The last few lines of a log, clipped. For "what is it doing right now"."""
    alloc_id = _resolve_alloc(alloc)
    lines = min(lines, MAX_RETURN_LINES)
    log, _ = nomad_log(alloc_id, task, max_bytes=1024 * 1024)
    tail = log.splitlines()[-lines:]
    return "\n".join(clip(strip_alibuild_prefix(line)) for line in tail) \
        or "(empty log)"


@mcp.tool()
def ci_check_status(check_name: str, repo: str) -> str:
    """How one check is doing across every open PR of a repo.

    Returns the per-PR verdicts plus the two aggregates that individual status
    pages cannot show: how the states break down, and whether many PRs are
    failing for the SAME stated reason -- which is the signature of a broken
    worker or image rather than of broken pull requests.
    """
    owner, _, name = repo.partition("/")
    data = github_graphql("""
    query($o:String!,$n:String!){repository(owner:$o,name:$n){
      pullRequests(states:OPEN,first:100,orderBy:{field:UPDATED_AT,direction:DESC}){
        nodes{number isDraft
          commits(last:1){nodes{commit{status{contexts{
            context state description createdAt}}}}}}}}}
    """, o=owner, n=name)
    rows, reasons = [], Counter()
    for pull in data["repository"]["pullRequests"]["nodes"]:
        commits = pull["commits"]["nodes"]
        status = commits[0]["commit"]["status"] if commits else None
        if not status:
            continue
        for ctx in status["contexts"]:
            if ctx["context"] != check_name:
                continue
            rows.append((ctx["createdAt"], pull["number"], ctx["state"],
                         (ctx["description"] or "")[:60]))
            if ctx["state"] in ("ERROR", "FAILURE") and (ctx["description"] or "").strip():
                reasons[ctx["description"].strip()] += 1
    if not rows:
        return "%s has posted on no open PR of %s" % (check_name, repo)
    rows.sort()
    out = ["%s on %s: %s" % (check_name, repo,
                             dict(Counter(r[2] for r in rows)))]
    for when, number, state, description in rows[-MAX_RETURN_LINES:]:
        out.append("  PR %-7d %-9s %s  %s" % (number, state.lower(), when[:16],
                                              description))
    for reason, count in reasons.most_common(3):
        if count >= 3:
            out.append("  NOTE: %d PRs failed with the same reason %r -- that is "
                       "usually the environment, not the PRs" % (count, reason))
    return "\n".join(out)


@mcp.tool()
def ci_pr(repo: str, number: int) -> str:
    """Every check on a PR's head commit, and which of them are red."""
    owner, _, name = repo.partition("/")
    data = github_graphql("""
    query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){
      pullRequest(number:$p){ title mergeable headRefOid
        commits(last:1){nodes{commit{status{contexts{
          context state description targetUrl}}}}}}}}
    """, o=owner, n=name, p=number)
    pull = data["repository"]["pullRequest"]
    commits = pull["commits"]["nodes"]
    status = commits[0]["commit"]["status"] if commits else None
    contexts = status["contexts"] if status else []
    red = [c for c in contexts if c["state"] in ("ERROR", "FAILURE")]
    out = ["%s#%d %.60s" % (repo, number, pull["title"]),
           "  head %.8s  mergeable=%s  %d checks, %d red"
           % (pull["headRefOid"], pull["mergeable"], len(contexts), len(red))]
    for ctx in sorted(contexts, key=lambda c: (c["state"] != "ERROR", c["context"])):
        out.append("  %-9s %-44s %s" % (ctx["state"].lower(), ctx["context"],
                                        (ctx["description"] or "")[:40]))
    return "\n".join(out[:MAX_RETURN_LINES])


@mcp.tool()
def ci_image(image: str) -> str:
    """A builder image's entrypoint and PATH, read from the registry.

    No pull: it fetches the config blob directly, so checking a multi-gigabyte
    builder costs two small requests. It also flags an empty PATH component,
    which is what "${PATH}:/usr/local/cuda/bin" leaves behind when the base
    image declared no PATH -- the slc10-gpu-builder bug, which presented as
    every aliBuild doctor check failing.
    """
    repo, _, tag = image.partition(":")
    repo = repo.replace("registry.cern.ch/", "")
    tag = tag or "latest"
    base = "https://registry.cern.ch"
    token = requests.get("%s/service/token" % base, timeout=30, params={
        "service": "harbor-registry", "scope": "repository:%s:pull" % repo,
    }).json().get("token", "")
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.docker.distribution.manifest.v2+json,"
                         "application/vnd.oci.image.manifest.v1+json"}
    manifest = requests.get("%s/v2/%s/manifests/%s" % (base, repo, tag),
                            headers=headers, timeout=30).json()
    digest = manifest.get("config", {}).get("digest")
    if not digest:
        return "no image config for %s:%s (%s)" % (repo, tag, str(manifest)[:120])
    config = requests.get("%s/v2/%s/blobs/%s" % (base, repo, digest),
                          headers=headers, timeout=60).json()
    env = config.get("config", {}) or {}
    path = next((e for e in env.get("Env") or [] if e.startswith("PATH=")), None)
    out = ["%s:%s" % (repo, tag),
           "  created:    %s" % config.get("created"),
           "  entrypoint: %s   cmd: %s" % (env.get("Entrypoint"), env.get("Cmd")),
           "  %s" % (path or "PATH ABSENT")]
    if path and (path == "PATH=" or path[5:].startswith(":") or "::" in path):
        out.append("  ^^ EMPTY PATH COMPONENT: ${PATH} expanded to nothing from "
                   "the base image. Everything relying on PATH will fail.")
    return "\n".join(out)


def main_task(alloc):
    """Which task in this allocation carries the build.

    Task names differ per job -- "ci" on the Linux checkers, something else on
    the macOS ones -- and asking for the wrong one is a 500 from the log API
    rather than a useful error. Prefer a task literally called "ci", else the
    last one still running, which for a group with prestart sidecars is the
    main one.
    """
    states = alloc.get("TaskStates") or {}
    if "ci" in states:
        return "ci"
    running = [name for name, state in states.items()
               if state.get("State") == "running"]
    return running[-1] if running else (max(states) if states else None)


def _resolve_alloc(prefix):
    """Accept a short allocation id, as the nomad CLI does."""
    if len(prefix) >= 36:
        return prefix
    for job in nomad_get("/v1/jobs"):
        for alloc in nomad_get("/v1/job/%s/allocations" % job["ID"]):
            if alloc["ID"].startswith(prefix):
                return alloc["ID"]
    raise ValueError("no allocation starting with %r" % prefix)


if __name__ == "__main__":
    mcp.run()
