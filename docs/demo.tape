# A demo of scute, recorded with charm VHS: https://github.com/charmbracelet/vhs
#
#   make demo
#
# Deterministic on purpose -- fixed dimensions, fixed typing speed, no clock on
# screen -- so that re-recording after a change produces a comparable GIF rather
# than a different one.

Output demo.gif
Set Shell bash
Set FontSize 16
Set Width 1100
Set Height 700
Set Padding 20
Set TypingSpeed 60ms
Set Theme "Catppuccin Mocha"

Hide
# The scute being demonstrated is the one just built, not whatever is installed:
# the recording moves to a temporary directory, so the repository has to be put
# on PATH before it goes. "make demo" does this too, for a tape run some other way.
Type "export PATH=$PWD/..:$PATH" Enter
Type "cd $(mktemp -d) && export PS1='$ ' && clear" Enter
Show

Type "# What can this host enforce?" Enter
Sleep 700ms
Type "scute doctor" Enter
Sleep 3s

Type "clear" Enter
Type "# Let scute work out what a command needs." Enter
Sleep 700ms
Type "scute learn --output scute.policy -- sh -c 'cat /etc/hostname > copy'" Enter
Sleep 3s
Type "cat scute.policy" Enter
Sleep 4s

Type "clear" Enter
Type "# Now run it under that policy." Enter
Sleep 700ms
Type "scute run --policy scute.policy -- sh -c 'cat /etc/hostname > copy && echo written'" Enter
Sleep 3s

Type "# And something the policy does not allow." Enter
Sleep 700ms
Type "scute run --policy scute.policy -- sh -c 'cat /etc/shadow'" Enter
Sleep 3s

Type "clear" Enter
Type "# Why? Ask." Enter
Sleep 700ms
Type "scute run --policy scute.policy --explain -- sh -c 'cat /etc/shadow'" Enter
Sleep 5s
