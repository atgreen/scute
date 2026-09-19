# A demo of scute, recorded with charm VHS: https://github.com/charmbracelet/vhs
#
#   make demo
#
# Deterministic on purpose -- fixed dimensions, fixed typing speed, no clock on
# screen -- so that re-recording after a change produces a comparable GIF rather
# than a different one.
#
# The recording is one Claude Code session, because that is the thing Scute is
# for: the agent is handed tokens that are worth nothing away from the broker,
# and a home directory it cannot read.  What it needs to run:
#
#   - claude on PATH, and KeyFence holding "anthropic"
#   - a "github" credential reaching the session as GH_TOKEN, which the shipped
#     claude policy does not ask for -- the machine this was recorded on adds it
#     with ~/.config/scute/policies/claude.d/10-github.policy:
#
#         [credentials.github]
#         ref = "github"
#         destinations = ["api.github.com"]
#         env = "GH_TOKEN"
#
# The tokens are on screen on purpose.  They are KeyFence's, minted for that run
# and revoked when it ended; the credentials they stand in for never leave the
# broker and are not in the recording.

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

Type "# Claude Code, confined to this directory, with its keys held by a broker." Enter
Sleep 2s
Type "# It gets no network of its own. An eBPF program on the sandbox's cgroup" Enter
Type "# rewrites every outbound connection to KeyFence, so a client that ignores" Enter
Type "# the proxy variables arrives there anyway -- and Landlock leaves no other" Enter
Type "# port to leave by." Enter
Sleep 4s
Type "scute claude" Enter

Hide
# Startup is hidden: several dull seconds, and possibly a question. Claude asks
# whether it trusts a directory it has not seen before, and it remembers the
# answer against /tmp rather than the temporary directory -- so the prompt comes
# once per machine and never again, which is why the wait accepts either screen.
# The Enter answers "Yes, I trust this folder" if it is up, and does nothing at
# an empty prompt if it is not.
#
# Ready is the permission-mode line under the input box rather than the
# "? for shortcuts" hint: this policy passes --dangerously-skip-permissions, and
# that line says so instead. The Escape is insurance against a tip overlay
# opening over the prompt; on an empty prompt it does nothing.
Wait+Screen@90s /Yes, I trust this folder|bypass permissions on/
Enter
Wait+Screen@90s /bypass permissions on/
Escape
Sleep 1s
Show
Sleep 2s

# Everything from here is typed into the agent's own session: "!" is Claude Code's
# shell prefix, so these run inside the sandbox, with the agent's environment,
# exactly as the agent's own commands do.

# What the agent holds.
Type "!"
Sleep 500ms
Type "env | grep TOKEN"
Sleep 800ms
Enter
Wait+Screen@30s /kf_/
Sleep 7s

# Not a credential -- and still enough to work. The request goes to the broker
# because the kernel sends it there, and the broker swaps the real token into the
# Authorization header on the way to api.github.com. The agent never holds it.
Type "!"
Sleep 500ms
Type "gh api user --jq .login"
Sleep 800ms
Enter
Sleep 9s

# The other half: an ordinary deny-by-default sandbox.  The policy grants this
# directory, so the rest of the home directory is not there to read.
Type "!"
Sleep 500ms
Type "ls -l ~/.ssh"
Sleep 800ms
Enter
# The refusal is the last thing on screen and the point of the whole recording,
# so it stays up long enough to read twice before the session goes.
Sleep 11s

# Out of the session: two interrupts, which is how Claude Code exits.
Ctrl+C
Sleep 700ms
Ctrl+C
Sleep 2s

Type "# Tokens, not keys. Every request went through the proxy that holds the" Enter
Type "# real credential, logged what was spent, and revoked both tokens when the" Enter
Type "# run ended. What was on screen authenticates nothing." Enter
Sleep 6s
