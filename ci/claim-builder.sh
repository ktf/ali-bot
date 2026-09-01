#!/bin/bash -x
# -*- sh-basic-offset: 2 -*-
# A build loop that takes work by CLAIMING it, rather than by owning a hash
# shard of it. The claimed counterpart of continuous-builder.sh.
#
# continuous-builder.sh is deliberately left alone: it drives every production
# builder, and the two differ in ways that cannot be expressed as a flag --
# which PRs a worker considers, how it avoids duplicating another worker, and
# whether it re-execs itself. Running them side by side is also what lets a
# single pool be migrated at a time. See ci/SCALING_PLAN.md, Phases 1-3.
#
# What it does each round:
#   1. optionally source $ROUND_SETUP, for credentials that expire;
#   2. refresh the *.env files from ali-bot@master;
#   3. list every buildable PR, in the order the lister recommends;
#   4. walk that list and build the FIRST one it can claim;
#   5. sleep only if it built nothing.
#
# Because every worker asks for the whole list and claims decide who builds
# what, workers need no coordination and no identity: add one and the queue
# drains faster, remove one and its claim lapses. That is the property the hash
# sharding cannot provide.
#
# Environment:
#   MESOS_ROLE, CUR_CONTAINER, ALIBOT_CONFIG_SUFFIX   which pool to serve
#   CUR_CONTAINERS  space-separated containers this worker serves, defaulting
#                  to just $CUR_CONTAINER. One worker can hold the queues of
#                  several platforms at once -- slc10 and ubuntu2204 say -- so
#                  retiring a per-platform builder does not retire its check.
#   GITHUB_TOKEN                                       (or via $ROUND_SETUP)
#   ROUND_SETUP    optional file SOURCED at the start of every round. Sourced,
#                  not run, so it can export credentials into this shell --
#                  which is the point: a gate token from a credential broker
#                  expires, and re-execing would carry a stale one forever.
#   IDLE_SLEEP     seconds to wait after a round that built nothing (300)
#   CLEANUP_MAX_AGE_DAYS   delete builds older than this, per round (2)
#   CLEANUP_MIN_FREE_GIB   emergency floor: if still below this much free,
#                          keep deleting until it is met (50). See below --
#                          an unreachable value wipes every work area.
#   HEARTBEAT      seconds between "still building X" lines on stdout (300);
#                  0 disables them

. build-helpers.sh
. claims.sh

: "${IDLE_SLEEP:=300}" "${TIMEOUT:=600}" "${LONG_TIMEOUT:=36000}"
: "${HEARTBEAT:=300}"
: "${CUR_CONTAINERS:=$CUR_CONTAINER}"

# What produces this round's candidate rows. Unquoted on use, so it carries its
# own flags; `-c <container>` is appended per container.
#
# The loop does not care what a "unit of work" is -- it claims a (check, sha)
# and hands it to build-one.sh -- so swapping the lister is enough to serve
# something other than pull requests. list-release-tags does exactly that for
# tagged releases, which is why this is a variable rather than a hardcoded call.
: "${LISTER:=list-branch-pr --all-groups --no-status}"

# The same identity continuous-builder.sh sets, for the same reason: the build
# MERGES the PR into the base branch, and git refuses to commit without one --
# "fatal: empty ident name". This lives in the entrypoint rather than in
# build-one.sh because it is per-worker setup, not per-PR.
#
# Left out of the first version of this script, which is what made the loop fail
# in setup on every round: the merge died before any compilation, so no build
# ever ran. Anything else continuous-builder.sh does once at startup belongs
# here too -- it is not a shared prologue, and nothing warns when it diverges.
git config --global user.name alibuild
git config --global user.email alibuild@cern.ch

# The claim key must be globally unique for a piece of work, and *.env names
# are not: o2-alidist exists under several pools. CHECK_NAME is the GitHub
# status context, which is unique by construction. Read it in a subshell so the
# env files cannot leak into the loop.
#
# Everything the loop needs about a check comes back from ONE subshell. Sourcing
# the env files is the expensive part, and it is now needed for ordering as well
# as for the claim, so it is done once per *.env per round rather than once per
# row -- a queue of 30 PRs across 2 checks costs 2 sourcings, not 30.
function check_env_for () (
  # "$container/$env". Everything downstream keys off this pair rather than the
  # bare *.env name, because o2-alidist exists under several containers and is a
  # DIFFERENT check in each -- different architecture, image and work area.
  # shellcheck disable=SC2030  # deliberately local to this subshell
  CUR_CONTAINER=${1%%/*}
  source_env_files "${1#*/}" > /dev/null 2>&1 || exit 0
  # '|' and not a tab: IFS treats runs of WHITESPACE as one delimiter, so a
  # check with no ONLY_PRS collapsed its empty field and shifted REQUIRES_POOL
  # into only_prs -- every GPU row then failed an allowlist it was never subject
  # to, and the worker skipped exactly the work it existed for, silently.
  printf '%s|%s|%s\n' "$CHECK_NAME" "${ONLY_PRS:-}" "${REQUIRES_POOL:-}"
)

# What this worker has already built, as "$check|$sha" lines.
#
# The loop's only other notion of "done" is the GitHub status the build posts,
# which the lister then sees and stops offering. That breaks down whenever the
# status does not get written -- SILENT mode during a bring-up, or a failing
# report-pr-errors -- and the failure mode is a LIVELOCK, not a slowdown: the
# just-built PR is still untested, still sorts first, and gets rebuilt forever
# while the rest of the queue starves. Observed on slc10: 11 builds of one PR
# in five minutes.
#
# The sharded loop never needed this because random.sample() picked a different
# PR each round, so a missing status cost one wasted rebuild rather than all of
# them. Walking an ordered list is what turns it fatal, and claiming is what
# makes the list ordered.
#
# Keyed by commit, so a new push is a new key and gets built.
#
# Entries EXPIRE, because a permanent block is a bigger hammer than the livelock
# needs. What separates the two cases is time: a missing status re-offers the
# same work within seconds, while a retry worth having -- a transient failure, a
# fixed dependency, an operator clearing a bad cache -- is wanted minutes or
# hours later. A cooldown keeps the first bounded (one rebuild per cooldown per
# worker instead of the 11-in-5-minutes above) and lets the second happen on its
# own.
#
# That matters most at count=1, where this variable IS the fleet's memory and a
# failed build parks the queue until a human restarts the allocation. With
# several workers the others were always free to pick the work up; a single
# worker has nobody to hand it to.
CLAIM_RETRY_COOLDOWN=${CLAIM_RETRY_COOLDOWN:-3600}
attempted=

# ---- what this worker is doing, on stdout -----------------------------------
#
# The build itself writes to stderr, and it writes a LOT: a slc10 round is
# ~230k lines, and Nomad rotates the capture by SIZE (3 files x 200 MB), so any
# line describing what is being built scrolls out of reach long before the build
# ends. Asking "what is this worker on?" then means reading hundreds of
# megabytes to find one line near the start.
#
# So stdout is kept as an index instead: a banner per round, and an identity
# line repeated every HEARTBEAT seconds while the build runs. Because the two
# streams are captured separately, `nomad alloc logs <alloc> ci` -- stdout, the
# default -- becomes a readable timeline of rounds, and -stderr stays the
# firehose. The repetition is the point: a BEGIN banner alone is no more
# reachable than the line it replaces, whereas a heartbeat means ANY bounded
# tail answers the question.
heartbeat_pid=

start_heartbeat() {          # round check pr sha
  # Idempotent by construction. A heartbeat that outlives its round is worse
  # than none: it keeps announcing a PR this worker has stopped building, and
  # the reader has no way to tell that line from a live one. Overwriting
  # heartbeat_pid without stopping the old process would leak exactly that, so
  # starting one always ends the previous one first, whatever path got us here.
  stop_heartbeat
  [ "$HEARTBEAT" -gt 0 ] 2>/dev/null || return 0
  # set +x inside: this loop would otherwise trace itself onto stderr every
  # interval, for hours, which is the noise we are trying to escape.
  #
  # One printf per line, and a short one: writes under PIPE_BUF are atomic, so
  # a heartbeat landing mid-banner interleaves whole lines rather than
  # splicing two together.
  ( set +x
    started=$SECONDS
    while sleep "$HEARTBEAT"; do
      # Local time, not UTC, and in aliBuild's own format. stdout and stderr
      # are captured into SEPARATE files, so their relative order is lost -- a
      # heartbeat and the compiler output it describes line up only by clock.
      # aliBuild timestamps in local time, so `date -u` here produced matching
      # text two hours out and sorted the two streams into the wrong order.
      printf '%s [round %s] check=%s pr=%s sha=%.8s elapsed=%sm\n' \
             "$(date '+%Y-%m-%d@%H:%M:%S')" \
             "$1" "$2" "$3" "$4" "$(( (SECONDS - started) / 60 ))"
    done ) &
  heartbeat_pid=$!
}

stop_heartbeat() {
  [ -n "$heartbeat_pid" ] || return 0
  # Killing the subshell is enough, even though it is almost always blocked in
  # sleep(1) and that sleep is orphaned rather than killed. The orphan cannot
  # produce a stale heartbeat: the printf lives in the subshell that just died,
  # so the sleep exits silently within one interval and reaps itself.
  #
  # NOT `kill -- -$pid`: without job control this script never enables (set -m),
  # a background subshell is not a process-group leader, so $! is a PID and no
  # process group by that id exists.
  kill "$heartbeat_pid" 2>/dev/null
  # Reap it, so a worker that runs for weeks does not accumulate one zombie per
  # round.
  wait "$heartbeat_pid" 2>/dev/null
  heartbeat_pid=
}

# A worker killed mid-build (Nomad stopping the task, or a restart) would
# otherwise leave the background loop behind.
trap stop_heartbeat EXIT INT TERM

round=0

while true; do
  round=$((round + 1))
  # Credentials that expire, refreshed before anything uses them.
  if [ -n "$ROUND_SETUP" ] && [ -r "$ROUND_SETUP" ]; then
    # shellcheck source=/dev/null
    . "$ROUND_SETUP"
  fi

  # The *.env files, from ali-bot@master exactly as the builders use.
  reset_git_repository ali-bot https://github.com/alisw/ali-bot || :

  # ...unless this worker is testing a candidate ali-bot, in which case the
  # config comes from the SAME ref as the code below. A PR is one thing: if it
  # changes a *.env and the script that reads it, testing them apart tests a
  # combination that will never be deployed.
  #
  # This is also what makes the override possible at all. INSTALL_ALIBOT is
  # *defined in* repo-config/DEFAULTS.env, so config fetched from master would
  # reset the pin on every round and the worker would quietly fall back to
  # master. The checkout has to move first.
  if [ -n "$ALIBOT_OVERRIDE" ]; then
    (
      cd ali-bot || exit 1
      # Detached, so reset_git_repository above leaves it alone from now on
      # (it only resets when HEAD is on a branch) and this block owns the
      # checkout. Re-fetched every round, so pushes to the PR are picked up.
      short_timeout git fetch -f "https://github.com/${ALIBOT_OVERRIDE%@*}" \
                    "+${ALIBOT_OVERRIDE#*@}:refs/ab" &&
        git checkout -f refs/ab && git clean -fxd
    ) || :
  fi

  # --all-groups because a worker must be able to walk past PRs other workers
  # have already claimed; the default output stops at the first group and would
  # leave this worker idle whenever its head entry was taken. --no-status keeps
  # the listing read-only: trust_pr would otherwise write a GitHub status from
  # here, and reporting belongs to the build, not to the survey.
  #
  # One listing per container, concatenated. The lister globs
  # repo-config/$ROLE/$CONTAINER/*.env, so it can only ever see one container at
  # a time; serving several means asking it once per container and stamping each
  # row with where it came from. The stamp goes in the *.env field, so the
  # ordering below -- which treats that field as an opaque key -- needs no
  # changes and cannot confuse two same-named checks for one.
  hashes=
  for _container in $CUR_CONTAINERS; do
    # shellcheck disable=SC2086  # LISTER is a command plus flags, it must word-split
    _rows=$(short_timeout $LISTER -c "$_container") || _rows=
    [ -n "$_rows" ] || continue
    _rows=$(printf '%s\n' "$_rows" | awk -v c="$_container" '{ $4 = c "/" $4; print }')
    hashes="${hashes:+$hashes$'\n'}$_rows"
  done

  # One lookup per *.env in this round's listing, reused for ordering, for the
  # ONLY_PRS filter and for the claim key below. Lines are
  # "env<TAB>check<TAB>only_prs<TAB>requires_pool".
  envinfo=
  if [ -n "$hashes" ]; then
    for _env in $(printf '%s\n' "$hashes" | awk '{print $4}' | sort -u); do
      envinfo="${envinfo:+$envinfo$'\n'}$_env|$(check_env_for "$_env")"
    done
  fi

  # Order the queue. The key is (group, specialisation, affinity, original
  # position):
  #
  #   group          the lister already puts untested PRs before rebuild
  #                  candidates, and that always wins -- a PR awaiting its first
  #                  verdict is what the queue exists for. Ranked by where the
  #                  lister first mentioned it, never by name, so a group this
  #                  code has not heard of cannot be silently reordered.
  #   specialisation a check pinned to THIS worker's node pool comes first,
  #                  because no other worker can take it. A GPU worker that
  #                  spends its time on work anybody could do leaves the GPU-only
  #                  queue to starve; workers with no pool of their own score
  #                  every row the same and are unaffected.
  #   affinity       then prefer the *.env built last. Everything expensive in a
  #                  work area is per-check -- sw/, the checkouts, the unpacked
  #                  tarballs -- so two builds of one check cost far less than
  #                  alternating, which evicts the other's tree each time.
  #   position       a stable final key, so staleness ordering survives inside
  #                  each bucket.
  #
  # With no pool and no previous build every row scores identically, so the order
  # is exactly what the lister produced.
  # Space-separated "env=pool" pairs, and only for checks that demand a pool --
  # usually none. NOT newline-separated: BSD awk rejects a newline inside -v, and
  # these scripts run on the macOS builders too.
  poolmap=$(printf '%s\n' "$envinfo" |
              awk -F'|' 'NF >= 4 && $4 != "" { printf "%s=%s ", $1, $4 }')

  if [ -n "$hashes" ]; then
    hashes=$(printf '%s\n' "$hashes" | awk -v pref="$last_env" -v pool="$WORKER_NODE_POOL" \
                 -v poolmap="$poolmap" '
      BEGIN { n = split(poolmap, pairs, " ")
              for (i = 1; i <= n; i++)
                if (split(pairs[i], kv, "=") == 2) needs[kv[1]] = kv[2] }
      { if (!($1 in grank)) grank[$1] = ++ngroups
        mine = (pool != "" && needs[$4] == pool) ? 0 : 1
        printf "%d\t%d\t%d\t%d\t%s\n", grank[$1], mine, ($4 == pref ? 0 : 1), NR, $0 }' |
      sort -k1,1n -k2,2n -k3,3n -k4,4n | cut -f5-)
  fi

  built=
  if [ -n "$hashes" ]; then
    # A marker, because "we did not get the claim" and "the build failed" are
    # indistinguishable from an exit status: nomad var lock returns the child's
    # status when it runs one, and its own when it does not.
    marker=$(mktemp -u "${TMPDIR:-/tmp}/claim-built.XXXXXX")
    while read -r build_type pr_number pr_hash env_key waiting_since; do
      [ -n "$env_key" ] || continue
      IFS='|' read -r _ check only_prs requires_pool < <(
        printf '%s\n' "$envinfo" | grep -m1 -F "$env_key|")
      [ -n "$check" ] || continue

      # Back to its two halves for the build. Exported, not passed: build-one.sh
      # sources the *.env files itself, and source_env_files reads the container
      # out of the environment.
      env_name=${env_key#*/}
      # shellcheck disable=SC2031  # set here for the build, not read back from the subshell above
      export CUR_CONTAINER=${env_key%%/*}

      # A check can demand a particular Nomad node pool, for work that is only
      # possible on certain hardware -- REQUIRES_POOL=gpu in its *.env. This is a
      # HARD filter, not the soft preference the sort applies: a worker outside
      # that pool must never claim the row, or it takes work it cannot do and
      # fails it.
      #
      # node_pool is a job-level field in Nomad, so "both pools" means two jobs
      # sharing one queue. Partitioning the checks by directory instead would
      # work, but then a GPU worker could not help with ordinary builds when the
      # GPU queue is empty -- and being able to is the whole point of claims.
      #
      # Unset (every check today except o2-gpu-test) means any worker may take
      # it, so a worker with no WORKER_NODE_POOL behaves exactly as before.
      if [ -n "$requires_pool" ] && [ "$requires_pool" != "$WORKER_NODE_POOL" ]; then
        continue
      fi

      # ONLY_PRS: a bring-up allowlist, set per check in its *.env, so the two
      # checks a worker serves can be restricted independently -- which is the
      # point, since bringing up a platform means running a handful of PRs on it
      # while everything else stays untouched.
      #
      # Empty (the normal case, and every production check) means no filtering
      # at all. Whitespace or commas separate entries, so "6294,6300" and
      # "6294 6300" both work.
      #
      # Deliberately here and not in list-branch-pr: the lister is shared with
      # the sharded builders, and a filter there would be one edit away from
      # silently narrowing what production considers. A worker skipping rows can
      # only ever make THIS worker do less.
      if [ -n "$only_prs" ]; then
        case " ${only_prs//,/ } " in
          *" $pr_number "*) : ;;
          *) continue ;;
        esac
      fi

      # Already built here, whether or not GitHub records it. A plain string
      # rather than an associative array: macOS builders still run bash 3.2.
      #
      # Rebuilt on every lookup so expired entries fall out: this list is only
      # ever appended to, and an allocation lives for weeks.
      _now=$(date +%s)
      _kept=
      _skip=
      while IFS='|' read -r _a_check _a_sha _a_when; do
        [ -n "$_a_check" ] || continue
        # An entry with no timestamp predates the cooldown; treat it as expired
        # rather than eternal, so a rolling upgrade cannot strand a worker.
        case $_a_when in ''|*[!0-9]*) continue ;; esac
        [ $((_now - _a_when)) -lt "$CLAIM_RETRY_COOLDOWN" ] || continue
        _kept="${_kept:+$_kept$'\n'}$_a_check|$_a_sha|$_a_when"
        # An if, not `[ ... ] && _skip=1`: as the last command in the body that
        # idiom returns non-zero whenever it does not match, which would end the
        # loop the day somebody adds set -e to this script.
        if [ "$_a_check|$_a_sha" = "$check|$pr_hash" ]; then
          _skip=1
        fi
      done <<EOF
$attempted
EOF
      attempted=$_kept
      unset _a_check _a_sha _a_when _kept _now
      if [ -n "$_skip" ]; then
        unset _skip
        continue
      fi
      unset _skip

      rm -f "$marker"
      # The banner goes out BEFORE the claim is attempted, because at this point
      # we do not yet know whether we will get it -- with_claim returns having
      # done nothing if another worker holds it. The END line below says which
      # happened, so a lost claim is one cheap pair of lines, not a mystery.
      printf '%s ===== ROUND %s BEGIN check=%s pr=%s sha=%.8s type=%s =====\n' \
             "$(date '+%Y-%m-%d@%H:%M:%S')" \
             "$round" "$check" "$pr_number" "$pr_hash" "$build_type"
      claim_started=$SECONDS
      start_heartbeat "$round" "$check" "$pr_number" "$pr_hash"
      BUILD_MARKER=$marker with_claim "$check" "$pr_hash" \
        build-one.sh "$env_name" "$build_type" "$pr_number" "$pr_hash" "$waiting_since"
      build_rc=$?
      stop_heartbeat
      # Marker, not exit status: with_claim returns the child's status when it
      # ran one and its own when it did not, so only the marker distinguishes
      # "built and failed" from "never got the claim".
      if [ -e "$marker" ]; then
        printf '%s ===== ROUND %s END pr=%s result=built rc=%s duration=%sm =====\n' \
               "$(date '+%Y-%m-%d@%H:%M:%S')" \
               "$round" "$pr_number" "$build_rc" \
               "$(( (SECONDS - claim_started) / 60 ))"
      else
        printf '%s ===== ROUND %s END pr=%s result=claim-lost =====\n' \
               "$(date '+%Y-%m-%d@%H:%M:%S')" "$round" "$pr_number"
      fi

      if [ -e "$marker" ]; then
        # We held the claim and the build ran. Re-list rather than walking on:
        # hours have passed and the queue we are holding is now a fossil.
        rm -f "$marker"
        # Recorded only when we actually built it. Losing the claim must NOT
        # count: another worker is building it, and if that worker dies this one
        # should still be able to pick it up on a later round.
        attempted="${attempted:+$attempted$'\n'}$check|$pr_hash|$(date +%s)"
        # What the work area is now warm for, used as the affinity tie-break on
        # the next round. Set from the build that RAN, not from the claim we
        # tried, so a claim lost to another worker cannot drag this one towards
        # a check it never actually built. The qualified key, because the warm
        # tree belongs to one container: slc10/o2-alidist being warm says
        # nothing about ubuntu2204/o2-alidist.
        last_env=$env_key
        built=1
        break
      fi
      # Otherwise somebody else holds it -- try the next entry immediately.
    done <<< "$hashes"
    rm -f "$marker"
  fi

  # Reclaim disk before the next round, not after the build that needs it.
  #
  # continuous-builder.sh has always done this; the claim loop was written fresh
  # and the step was never carried across. The cost of the omission, measured on
  # alimetal01 on 2026-08-28: two allocations holding 746 and 902 GiB, a root
  # filesystem at 95%, and rounds failing not on anything they built but on
  # `pip install ali-bot` -- "fatal: Unable to create temporary file ...: No
  # space left on device". `aliBuild clean` runs every round and does not touch
  # this: it only prunes BUILD dirs already unreferenced, whereas what grows is
  # the *referenced* ones -- every past build keeps its <pkg>-latest symlink, so
  # nothing it produced is ever collectable. Deleting those symlinks by age is
  # what makes the trees behind them collectable, and it is the whole win: on
  # alimetal01, ageing out 94 stale o2-alidist-dataflow builds took the
  # filesystem from 85 GiB free to 704 GiB, 95% to 61%.
  #
  # -r "$_container": cleanup.py expects build directories named after *.env
  # files directly under its ci-root, and defaults that to ".". True for the
  # sharded builders, which have <check>/sw -- but build-one.sh nests one level
  # deeper here, mkdir -p "$CUR_CONTAINER/$env_name", so ci-root has to be the
  # container directory or it silently finds nothing to clean.
  #
  # Once per container because the argument is singular. The -f pass measures
  # real free space, so later iterations no-op once the threshold is met; the -t
  # pass still ages out each container's own old builds.
  #
  # -f is an emergency floor, deliberately set below normal operating range --
  # not a target to aim for. cleanup_to_disk_threshold() stops on `not symlinks
  # or disk_free >= target`, so a target it cannot reach is not a partial
  # cleanup: it deletes EVERY symlink it gathered, across every container, and
  # only then gives up. On a node sitting under the threshold that repeats each
  # round, so every build is permanently cold -- hours per O2 build, forever.
  # 100 would have done exactly that on alimetal01, which ran at 85 GiB free.
  # Routine reclamation is -t's job; -f exists for the case where age alone did
  # not free enough and a cold rebuild beats a full disk.
  #
  # Between rounds and never during one: the loop builds a single check at a
  # time, so every other work area is idle at this point.
  for _container in $CUR_CONTAINERS; do
    [ -d "$_container" ] || continue
    cleanup.py -t "${CLEANUP_MAX_AGE_DAYS:-2}" -f "${CLEANUP_MIN_FREE_GIB:-50}" \
               -r "$_container" "$MESOS_ROLE" "$_container" || true
  done
  unset _container

  # Only idle when there was genuinely nothing to take. After a build, loop
  # straight back: there may be more work, and the caches are warm right now.
  [ -n "$built" ] || sleep "$IDLE_SLEEP"
done
