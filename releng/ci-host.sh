#!/bin/sh
# Make a CI runner look, to Scute, like the workstation it was written for, and
# then run the command given to it:
#
#   releng/ci-host.sh make check
#
# Two things a hosted runner does not hand an ordinary user, and the suite is
# not willing to do without: unprivileged user namespaces, and a cgroup of its
# own to put limits in.  Neither is a property of Scute, so arranging them here
# is not the suite being lenient -- every test still runs, and still fails if
# the kernel refuses what a policy asked for.
#
# It wants sudo, and is meant for a machine you are willing to rearrange.  On a
# workstation, a login session already provides both and this script has nothing
# to do; run it there and it says so rather than changing anything.

set -eu

[ $# -gt 0 ] || { echo "usage: $0 command [argument ...]" >&2; exit 2; }

say() { printf '  %-28s %s\n' "$1" "$2"; }

echo "ci-host: preparing $(uname -r)"

# Ubuntu 24.04 confines unprivileged user namespaces with AppArmor, and a
# sandbox that cannot make one is a sandbox that cannot start.  Older kernels
# have neither the knob nor the restriction, so its absence is not a failure.
if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
  sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
  say "unprivileged userns" "unconfined"
else
  say "unprivileged userns" "not restricted by this kernel"
fi

# Scute puts a sandbox's limits in a cgroup beneath its own, which means its own
# has to be one it may write to -- what systemd calls a delegated scope, and what
# a login session already has.  A runner's job cgroup belongs to root, so make
# one, hand it over, and step into it: everything exec'd below inherits it.
cgroup=/sys/fs/cgroup
if [ ! -e "$cgroup/cgroup.controllers" ]; then
  echo "ci-host: $cgroup is not a cgroup-v2 mount" >&2
  exit 1
fi

own=$(sed -n 's/^0:://p' /proc/self/cgroup)
if [ -w "$cgroup$own" ]; then
  say "cgroup" "$own is already ours"
else
  # A controller can only be enabled below a cgroup whose parent enabled it, so
  # the root of the tree we can see has to offer what the delegated cgroup will
  # hand to its children.
  want=""
  for controller in cpu memory pids; do
    case " $(cat "$cgroup/cgroup.controllers") " in
      *" $controller "*) want="$want +$controller" ;;
    esac
  done

  # Inside a container the visible root is not the kernel's, so the rule that a
  # cgroup holding processes may not give controllers to its children applies to
  # it -- and it holds every process in the container, this one included.  Move
  # them aside and the root becomes an ordinary empty parent.  On a real host the
  # first write succeeds and nothing is rearranged.
  if ! echo "$want" | sudo tee "$cgroup/cgroup.subtree_control" >/dev/null 2>&1; then
    sudo mkdir -p "$cgroup/init"
    # Until it is empty rather than once through: cgroup.procs is generated as
    # it is read, so moving a process partway through a pass hides the ones
    # behind it.  A pass that moves nothing is as empty as it is going to get.
    while pids=$(cat "$cgroup/cgroup.procs"); [ -n "$pids" ]; do
      moved=no
      for pid in $pids; do
        if echo "$pid" | sudo tee "$cgroup/init/cgroup.procs" >/dev/null 2>&1; then
          moved=yes
        fi
      done
      [ "$moved" = yes ] || break
    done
    echo "$want" | sudo tee "$cgroup/cgroup.subtree_control" >/dev/null
    say "cgroup root" "emptied into /init so it can hand out$want"
  fi

  scope=$cgroup/scute-ci.scope
  sudo mkdir -p "$scope"
  # Ownership of the directory and of these files is exactly what delegation
  # means: the owner may make cgroups, move processes, and decide which
  # controllers its children get.
  sudo chown -R "$(id -u):$(id -g)" "$scope"
  echo $$ | sudo tee "$scope/cgroup.procs" >/dev/null
  say "cgroup" "delegated /scute-ci.scope (controllers: $(cat "$scope/cgroup.controllers"))"
fi

exec "$@"
