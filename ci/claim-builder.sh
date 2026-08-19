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
#   GITHUB_TOKEN                                       (or via $ROUND_SETUP)
#   ROUND_SETUP    optional file SOURCED at the start of every round. Sourced,
#                  not run, so it can export credentials into this shell --
#                  which is the point: a gate token from a credential broker
#                  expires, and re-execing would carry a stale one forever.
#   IDLE_SLEEP     seconds to wait after a round that built nothing (300)

. build-helpers.sh
. claims.sh

: "${IDLE_SLEEP:=300}" "${TIMEOUT:=600}" "${LONG_TIMEOUT:=36000}"

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
# ONLY_PRS comes back from the same subshell rather than a second one: this runs
# once per row of the listing, and sourcing the env files twice per row to read
# two variables would double that cost for nothing.
function check_env_for () (
  source_env_files "$1" > /dev/null 2>&1 || exit 0
  printf '%s\t%s\n' "$CHECK_NAME" "${ONLY_PRS:-}"
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
# Keyed by commit, so a new push is a new key and gets built. The cost is that
# one worker will not rebuild an identical (check, sha) twice in a session,
# which production does at random to catch flaky failures -- worth losing, since
# it only delays a retry until this allocation restarts, whereas a livelock
# stops the queue outright.
attempted=

while true; do
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
  hashes=$(short_timeout list-branch-pr --all-groups --no-status) || hashes=

  # Cache affinity: prefer the *.env this worker built last. Everything
  # expensive in a work area is per-check -- sw/, the git checkouts, the
  # unpacked tarballs -- so building o2-alidist twice in a row costs a fraction
  # of alternating between two checks, which evicts the other's tree each time.
  #
  # Strictly a TIE-BREAK, never a reordering of the groups: the lister already
  # emits untested PRs before rebuild candidates, and an untested PR of another
  # check must still outrank a warm rebuild -- a PR waiting for its first verdict
  # is what the queue exists for. So the sort key is (group, affinity, original
  # position), with the group ranked by where the lister first mentioned it
  # rather than by name, so this cannot silently reorder groups it has not heard
  # of. A stable third key keeps the staleness ordering inside each bucket.
  #
  # Empty on the first round, and then every row scores the same, so the order is
  # exactly what the lister produced.
  if [ -n "$hashes" ] && [ -n "$last_env" ]; then
    hashes=$(printf '%s\n' "$hashes" | awk -v pref="$last_env" '
      { if (!($1 in grank)) grank[$1] = ++ngroups
        printf "%d\t%d\t%d\t%s\n", grank[$1], ($4 == pref ? 0 : 1), NR, $0 }' |
      sort -k1,1n -k2,2n -k3,3n | cut -f4-)
  fi

  built=
  if [ -n "$hashes" ]; then
    # A marker, because "we did not get the claim" and "the build failed" are
    # indistinguishable from an exit status: nomad var lock returns the child's
    # status when it runs one, and its own when it does not.
    marker=$(mktemp -u "${TMPDIR:-/tmp}/claim-built.XXXXXX")
    while read -r build_type pr_number pr_hash env_name waiting_since; do
      [ -n "$env_name" ] || continue
      IFS=$'\t' read -r check only_prs < <(check_env_for "$env_name")
      [ -n "$check" ] || continue

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
      case $'\n'"$attempted"$'\n' in
        *$'\n'"$check|$pr_hash"$'\n'*) continue ;;
      esac

      rm -f "$marker"
      BUILD_MARKER=$marker with_claim "$check" "$pr_hash" \
        build-one.sh "$env_name" "$build_type" "$pr_number" "$pr_hash" "$waiting_since" || :

      if [ -e "$marker" ]; then
        # We held the claim and the build ran. Re-list rather than walking on:
        # hours have passed and the queue we are holding is now a fossil.
        rm -f "$marker"
        # Recorded only when we actually built it. Losing the claim must NOT
        # count: another worker is building it, and if that worker dies this one
        # should still be able to pick it up on a later round.
        attempted="${attempted:+$attempted$'\n'}$check|$pr_hash"
        # What the work area is now warm for, used as the affinity tie-break on
        # the next round. Set from the build that RAN, not from the claim we
        # tried, so a claim lost to another worker cannot drag this one towards
        # a check it never actually built.
        last_env=$env_name
        built=1
        break
      fi
      # Otherwise somebody else holds it -- try the next entry immediately.
    done <<< "$hashes"
    rm -f "$marker"
  fi

  # Only idle when there was genuinely nothing to take. After a build, loop
  # straight back: there may be more work, and the caches are warm right now.
  [ -n "$built" ] || sleep "$IDLE_SLEEP"
done
