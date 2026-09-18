#!/bin/sh
# Grant scute the two capabilities its address-level egress guard needs.
#
#   releng/grant-capabilities.sh [path-to-scute]
#
# Loading a BPF program needs CAP_BPF; attaching one to a cgroup needs
# CAP_NET_ADMIN.  Nothing else scute does wants a privilege, and it drops
# every capability it holds before the sandboxed command exists.
#
# Not a setuid wrapper, and not a setuid script -- Linux ignores the setuid bit
# on anything with a shebang, and a setuid binary that execs scute would hand it
# root rather than two capabilities.  File capabilities give exactly these two
# and nothing else.

set -eu

scute=$(readlink -f "${1:-./scute}")
[ -x "$scute" ] || { echo "grant: $scute is not executable" >&2; exit 1; }

# Capabilities live on the inode, so every rebuild drops them.  Say so, because
# the symptom of forgetting is a policy that suddenly cannot be enforced.
echo "grant: $scute"
echo "grant: note: rebuilding scute replaces this file and loses these"
echo "grant: capabilities.  Re-run this script after make."
sudo setcap cap_bpf,cap_net_admin+ep "$scute"
getcap "$scute"

# A capability on a binary anyone may run is a capability anyone may use, and
# CAP_BPF is close enough to root that it is worth saying so out loud.
mode=$(stat -c %A "$scute")
case "$mode" in
  *x*x) echo "grant: note: $scute is executable by others ($mode)." >&2
        echo "grant: CAP_BPF is close to root; restrict the binary if this host" >&2
        echo "grant: has users who should not have it -- chmod 750, chown a group." >&2 ;;
esac
