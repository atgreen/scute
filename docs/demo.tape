# A demo of scute, recorded with charm VHS: https://github.com/charmbracelet/vhs
#
#   make demo
#
# Deterministic on purpose -- fixed dimensions, fixed typing speed, no clock on
# screen -- so that re-recording after a change produces a comparable GIF rather
# than a different one.
#
# It needs KeyFence running with a credential registered as "github", because
# that is what the recording is about: the agent holds a token, the broker holds
# the credential, and a token taken out of the sandbox is worth nothing.

Output demo.gif
Set Shell bash
Set FontSize 16
Set Width 1100
Set Height 700
Set Padding 20
Set TypingSpeed 55ms
Set Theme "Catppuccin Mocha"

Hide
# The scute being demonstrated is the one just built, not whatever is installed:
# the recording moves to a temporary directory, so the repository has to be put
# on PATH before it goes. "make demo" does this too, for a tape run some other way.
Type "export PATH=$PWD/..:$PATH" Enter
Type "cd $(mktemp -d) && export PS1='$ ' && clear" Enter
Show

Type "# An agent, confined, in one command -- with KeyFence holding its keys." Enter
Sleep 600ms
Type "scute policies" Enter
Sleep 3s
Type "# scute claude. scute codex. Each name is a policy you can read." Enter
Sleep 2500ms

Type "clear" Enter
Type "# Here is what one says. Nothing implicit, and no key in it." Enter
Sleep 600ms
Type "cat > agent.policy <<'EOF'" Enter
Type '[filesystem]' Enter
Type 'read-execute = ["/usr"]' Enter
Type 'read = ["/etc", "/proc"]' Enter
Type 'read-write = [".", "/dev/null"]' Enter
Type '' Enter
Type '[credentials.github]' Enter
Type 'ref = "github"                    # the name KeyFence holds it under' Enter
Type 'destinations = ["api.github.com"]' Enter
Type 'env = "GH_TOKEN"' Enter
Type "EOF" Enter
Sleep 2500ms

Type "clear" Enter
Type "# No [network] table, so every connection goes through KeyFence -- and" Enter
Type "# the kernel puts it there: an eBPF program rewrites the destination, so a" Enter
Type "# client that ignores the proxy variables still arrives at the broker." Enter
Sleep 2500ms
Type "# So what does the agent hold?" Enter
Sleep 600ms
Type "scute run --policy agent.policy -- printenv GH_TOKEN" Enter
Sleep 3s

Type "# Not your credential. It still works, because the broker swaps the real" Enter
Type "# one in on the way past:" Enter
Sleep 600ms
Type "cat > whoami.sh <<'EOF'" Enter
Type '/usr/bin/curl -s -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/user | grep login' Enter
Type "EOF" Enter
Type "scute run --policy agent.policy -- /usr/bin/sh whoami.sh" Enter
Sleep 5s

Type "clear" Enter
Type "# The credential is half of it. The other half is an ordinary sandbox." Enter
Sleep 1s
Type "# Landlock: a path the policy never named does not exist for it." Enter
Sleep 600ms
Type "scute run --policy agent.policy -- cat ~/.ssh/id_ed25519" Enter
Sleep 2500ms
Type "# seccomp: it cannot build itself a sandbox to escape into, either." Enter
Sleep 600ms
Type "scute run --policy agent.policy -- unshare --user true" Enter
Sleep 2500ms
Type "# Namespaces of its own -- user, mount, pid, uts, net -- and cgroup limits" Enter
Type "# the policy can set: memory, processes, CPU, wall clock." Enter
Sleep 2500ms

Type "clear" Enter
Type "# Now steal it. Take the token out of the sandbox and use it yourself." Enter
Sleep 1s
Type "cat > print-token.sh <<'EOF'" Enter
Type 'printf %s "$GH_TOKEN"' Enter
Type "EOF" Enter
Type "STOLEN=$(scute run --policy agent.policy -- /usr/bin/sh print-token.sh)" Enter
Sleep 3s
Type 'curl -s -o /dev/null -w "github says %{http_code}\n" -H "Authorization: Bearer $STOLEN" https://api.github.com/user' Enter
Sleep 4s
Type "# 401. Locked to one destination through the broker, and revoked when the" Enter
Type "# run ended. An exfiltrated token is worth nothing." Enter
Sleep 4s
