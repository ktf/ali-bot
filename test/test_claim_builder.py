"""Pin that the claim loop makes progress when GitHub records nothing.

claim-builder.sh walks an ordered list and builds the first PR it can claim.
Its only *external* notion of "this one is done" is the status the build posts,
which the lister then sees and stops offering. Whenever that status is not
written -- SILENT mode during a bring-up, or a failing report-pr-errors -- the
just-built PR is still untested, still sorts first, and is picked again.

The result is a livelock rather than a slowdown: one PR is rebuilt forever and
the rest of the queue starves. Observed on slc10 before the fix: eleven builds
of PR 4966 in five minutes, on a sixteen-core node.

The sharded loop never needed protecting from this, because random.sample()
picked a different PR each round, so a missing status cost one wasted rebuild
instead of every one of them. Walking an *ordered* list is what turns it fatal,
which is why the test arrived with the claim loop and not before.

The lister stub here deliberately returns the same three PRs every time: that is
exactly what GitHub looks like when the status never gets written.
"""

import os
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAIM_BUILDER = os.path.join(REPO, "ci", "claim-builder.sh")

PRS = [("4966", "sha-aaa"), ("5182", "sha-bbb"), ("5838", "sha-ccc")]

HELPERS = """\
short_timeout () { "$@"; }
reset_git_repository () { :; }
source_env_files () { export CHECK_NAME="build/O2/alidist-slc10-x86"; }
"""

# Always wins the claim and always "builds", so the only thing under test is
# which PR the loop chooses next.
CLAIMS = """\
with_claim () {
  local check=$1 sha=$2; shift 2
  echo "$sha" >> "$LOGFILE"
  [ -n "$BUILD_MARKER" ] && : > "$BUILD_MARKER"
  return 0
}
"""

LISTER = "#!/bin/bash\n" + "".join(
    "printf 'untested\\t%s\\t%s\\to2-alidist\\t168243708%d\\n'\n" % (num, sha, i)
    for i, (num, sha) in enumerate(PRS))


class ClaimBuilderProgressTestCase(unittest.TestCase):
    #: Every assertion here reads the same run, because the run costs wall-clock
    #: (the loop has to be timed out) and nothing below mutates it.
    ORDER = None

    @classmethod
    def setUpClass(cls):
        cls.ORDER = cls.run_loop()

    @staticmethod
    def run_loop(seconds=4):
        """Run the real claim-builder.sh against stubs; return what it built."""
        with tempfile.TemporaryDirectory() as tree:
            binpath = os.path.join(tree, "bin")
            os.mkdir(binpath)
            for name, body in (("build-helpers.sh", HELPERS),
                               ("claims.sh", CLAIMS),
                               ("list-branch-pr", LISTER)):
                path = os.path.join(binpath, name)
                with open(path, "w") as handle:
                    handle.write(body)
                os.chmod(path, 0o755)

            log = os.path.join(tree, "built.log")
            open(log, "w").close()
            env = dict(os.environ,
                       PATH=binpath + os.pathsep + os.environ["PATH"],
                       LOGFILE=log, IDLE_SLEEP="1", HOME=tree)
            # The loop never exits by design, so stop it and read what it did.
            try:
                subprocess.run(["bash", CLAIM_BUILDER], env=env, timeout=seconds,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                pass
            with open(log) as handle:
                return handle.read().split()

    def test_every_pr_is_built_even_though_no_status_is_recorded(self):
        """The queue drains although the lister's answer never changes."""
        built = self.ORDER
        self.assertEqual(sorted(set(built)), sorted(sha for _, sha in PRS),
                         "expected every PR to be built; got %r" % (built,))

    def test_no_pr_is_built_twice(self):
        """The regression. Unfixed, this logs one PR several hundred times."""
        built = self.ORDER
        repeated = {sha for sha in built if built.count(sha) > 1}
        self.assertFalse(repeated,
                         "rebuilt %s without any new commit -- the loop is not "
                         "advancing, which starves the rest of the queue"
                         % sorted(repeated))

    def test_it_stops_instead_of_spinning_once_everything_is_built(self):
        """Having exhausted the queue it must idle, not re-walk it.

        Bounded well above the three real builds but far below the hundreds a
        spinning loop reaches, so this fails on a hot loop without being timing
        sensitive.
        """
        built = self.ORDER
        self.assertLess(len(built), 10,
                        "%d builds for %d PRs means the loop is spinning"
                        % (len(built), len(PRS)))

    def test_the_git_identity_is_set(self):
        """Without it the PR merge dies with 'fatal: empty ident name' before
        any compilation, which is how the first slc10 deployment failed."""
        with open(CLAIM_BUILDER) as handle:
            body = handle.read()
        self.assertIn("git config --global user.name", body)
        self.assertIn("git config --global user.email", body)


if __name__ == "__main__":
    unittest.main()
