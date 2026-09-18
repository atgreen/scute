#!/bin/sh
# A smoke test for the built binary, run the way a stranger would meet it: in a
# clean environment, from a directory it has never seen, with nothing of the
# build tree in scope.
#
#   make smoke            # or: releng/smoke.sh ./scute
#
# It checks the things a package would be broken by and the suite would not
# notice: that the binary runs at all outside the developer's shell, that its
# runtime dependencies are present, and that a policy allows and denies what it
# says it does.

set -eu

scute=$(readlink -f "${1:-./scute}")
[ -x "$scute" ] || { echo "smoke: $scute is not executable"; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

say() { printf '  %-42s %s\n' "$1" "$2"; }
fail() { printf 'smoke: %s\n' "$1" >&2; exit 1; }

# Nothing from the invoking shell: no PATH tricks, no library paths, no policy
# picked up from the environment.
clean() { env -i HOME="$work" PATH=/usr/bin:/bin TERM=dumb "$@"; }

echo "smoke: $scute"

interpreter=$(readelf -p .interp "$scute" 2>/dev/null | awk '/\// { print $NF; exit }')
case "$interpreter" in
  /lib*|/usr/lib*|"") say "interpreter" "${interpreter:-static}" ;;
  *) say "interpreter" "$interpreter"
     echo "smoke: warning: built against a toolchain outside the system prefix;" >&2
     echo "smoke: this binary will not run where that prefix is absent." >&2 ;;
esac

clean "$scute" --version >/dev/null || fail "it will not start in a clean environment"
say "starts clean" "$(clean "$scute" --version)"

clean "$scute" doctor --json > doctor.json || fail "doctor says this host cannot sandbox"
grep -q '"ready": true' doctor.json || fail "doctor did not report the host ready"
say "doctor" "ready"

cat > scute.policy <<'POLICY'
[filesystem]
read-execute = ["/usr"]
read = ["/etc"]
read-write = ["."]

[network]
mode = "none"
POLICY

clean "$scute" run --policy scute.policy -- /bin/sh -c 'echo written > witness' \
  || fail "a write the policy allows was refused"
[ -f witness ] || fail "the allowed write did not happen"
say "allowed write" "witness"

if clean "$scute" run --policy scute.policy -- /bin/sh -c 'cat /root/.ssh/id_rsa' 2>/dev/null; then
  fail "reading outside the policy was allowed"
fi
say "denied read" "/root/.ssh/id_rsa"

if clean "$scute" run --policy scute.policy -- \
     /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' 2>/dev/null; then
  fail "the sandbox reached the network"
fi
say "denied network" "1.1.1.1:53"

status=0
clean "$scute" run --policy scute.policy -- /bin/sh -c 'exit 42' || status=$?
[ "$status" -eq 42 ] || fail "exit status was $status rather than 42"
say "exit status" "42"

clean "$scute" learn --output learned.policy -- /bin/sh -c 'cat /etc/hostname > copy' \
  || fail "learning failed"
grep -q '^\[filesystem\]' learned.policy || fail "learning wrote no policy"
clean "$scute" run --policy learned.policy -- /bin/sh -c 'cat /etc/hostname > copy' \
  || fail "the command failed under the policy learned from it"
say "learn and re-run" "$(grep -c . learned.policy) lines"

# Everything below is something the README claims.  If a claim stops being true,
# this is where it should be noticed -- not by a reader trying it.

clean "$scute" check --policy scute.policy . /etc >/dev/null \
  || fail "check refused paths the policy allows"
if clean "$scute" check --policy scute.policy /root >/dev/null 2>&1; then
  fail "check accepted a path the policy does not allow"
fi
say "check" "allowed and denied"

clean "$scute" run --policy scute.policy --dry-run -- /bin/sh -c 'echo nope > witness2' \
  > plan.txt || fail "--dry-run failed"
grep -q '^command' plan.txt || fail "--dry-run printed no plan"
if [ -f witness2 ]; then fail "--dry-run ran the command"; fi
say "--dry-run" "printed a plan, ran nothing"

printf '[filesystem]\nread-execute = ["/usr"]\n' > narrow.policy
# Expected to fail: that is the point of asking why.
clean "$scute" run --policy narrow.policy --explain -- /bin/sh -c 'cat /etc/hostname' \
  > explain.txt 2>&1 || true
grep -q 'refused' explain.txt || fail "--explain did not report a refusal"
grep -q 'read = ' explain.txt || fail "--explain suggested no rule"
say "--explain" "named what was refused"

printf '[filesystem]\nread-execute = ["/usr"]\nread = ["/etc"]\nread-write = [".", "/dev/null"]\n\n[audit]\nevents = ["exec", "open"]\n' > audited.policy
clean "$scute" run --policy audited.policy --audit trail.jsonl -- /bin/sh -c 'cat /etc/hostname > copy2' \
  || fail "an audited run failed"
grep -q '"event": "exec"' trail.jsonl || fail "the audit trail recorded no exec"
say "audit trail" "$(grep -c . trail.jsonl) records"

status=0
clean "$scute" run --namespaces-only --timeout 1s -- /bin/sleep 60 >/dev/null 2>&1 || status=$?
[ "$status" -eq 124 ] || fail "a command stopped for time exited $status rather than 124"
say "--timeout" "124"

AWS_SECRET_ACCESS_KEY=hunter2 clean "$scute" run --policy scute.policy -- \
  /bin/sh -c 'test -z "$AWS_SECRET_ACCESS_KEY"' \
  || fail "a secret in the environment reached the command"
say "environment" "secrets dropped"

clean "$scute" completions bash > completions.bash || fail "completions failed"
bash -n completions.bash || fail "the completions are not valid bash"
clean "$scute" man > scute.1 || fail "man failed"
if command -v groff >/dev/null; then
  groff -man -Tutf8 -ww scute.1 >/dev/null 2>groff.err || fail "groff rejected the manual page"
  if [ -s groff.err ]; then fail "groff complained about the manual page"; fi
fi
say "completions and man" "valid"

echo "smoke: all good"
