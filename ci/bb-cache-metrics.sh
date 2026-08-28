#!/bin/bash -e
# Report Buildbarn action-cache effectiveness for THIS node, to Mimir.
#
# bb-storage exposes Prometheus on 127.0.0.1:9980 (enablePrometheus in
# bb-services.nomad), but loopback-only, so it can only be read from the node
# itself -- hence a collector per node rather than a central scrape.
#
# The series that answers "is the cache working" is one family split by
# grpc_code:
#
#   buildbarn_blobstore_blob_access_operations_duration_seconds_count{
#       storage_type="ac", operation="Get", grpc_code="OK"}        -> hit
#       storage_type="ac", operation="Get", grpc_code="NotFound"}  -> miss
#       storage_type="ac", operation="Put", grpc_code="OK"}        -> upload
#
# Pushed as COUNTERS, not a precomputed ratio: they reset whenever bb-storage
# restarts, so the only honest reading is a rate over a window, and that is
# Mimir's job. A ratio computed here would silently step to nonsense after a
# restart -- alimetal03's did exactly that on 2026-08-27.
#
# ONE round per invocation, deliberately: the caller re-resolves
# OTLP_WRITE_TOKEN before each round because the gate token rotates daily, so a
# collector that looped internally would keep using the token it started with
# and start failing a day later, silently. Same shape as queue-metrics.sh
# --once.
#
# Environment:
#   OTLP_METRICS_URL, OTLP_WRITE_TOKEN   resolved per round by the caller
#   BB_METRICS_URL                       override for testing

. build-helpers.sh

: "${BB_METRICS_URL:=http://127.0.0.1:9980/metrics}"

# Parse the three counters out of a Prometheus text exposition on stdin.
# Prints "hit miss put", or nothing if the family is absent -- which is the
# correct answer for a bb-storage that has served no action-cache traffic yet,
# and is distinguishable from a failed scrape by the caller.
bb_parse_ac_counters () {
  python3 -c '
import re, sys

want = {("Get", "OK"): 0.0, ("Get", "NotFound"): 0.0, ("Put", "OK"): 0.0}
seen = False
metric = "buildbarn_blobstore_blob_access_operations_duration_seconds_count"

for line in sys.stdin:
    if not line.startswith(metric):
        continue
    labels, _, value = line.rpartition("}")
    tags = dict(re.findall(r'"'"'(\w+)="([^"]*)"'"'"', labels))
    if tags.get("storage_type") != "ac":
        continue
    key = (tags.get("operation"), tags.get("grpc_code"))
    if key in want:
        # Summed across backend_type: a node may report more than one backend,
        # and what we are after is the node total.
        want[key] += float(value)
        seen = True

if seen:
    print("%d %d %d" % (want[("Get", "OK")], want[("Get", "NotFound")],
                        want[("Put", "OK")]))
'
}

host=$(hostname -s)

# A scrape failure is a fact worth recording, not a reason to die: a node
# whose bb-storage is down should show up as bb_cache_scrape_ok=0 rather than
# as a gap indistinguishable from the collector itself being broken.
if body=$(curl -fsS --max-time 10 "$BB_METRICS_URL" 2>/dev/null); then
  scrape_ok=1
else
  scrape_ok=0
  body=
fi

counters=$(printf '%s\n' "$body" | bb_parse_ac_counters) || counters=

if [ -n "$counters" ]; then
  read -r hits misses puts <<< "$counters"
  otlp-push.py bb_cache "host=$host" -- \
    "ac_get_hit_total=$hits" "ac_get_miss_total=$misses" \
    "ac_put_total=$puts" "scrape_ok=$scrape_ok" ||
    echo "bb-cache-metrics: push failed, dropping this round" >&2
else
  # Reached bb-storage but it reports no action-cache traffic yet, or we could
  # not reach it at all. Either way the counters are unknown, so send only the
  # liveness flag rather than inventing zeros that would look like a cache
  # serving nothing.
  otlp-push.py bb_cache "host=$host" -- "scrape_ok=$scrape_ok" ||
    echo "bb-cache-metrics: push failed, dropping this round" >&2
fi
