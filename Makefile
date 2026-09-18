# SBCL is overridable because the binary inherits its toolchain: a Lisp
# installed under a private prefix produces an executable that will not run
# where that prefix is absent.  releng/smoke.sh says so if it happens.
SBCL ?= sbcl

# A changed system definition gets a full recompile.  Reordering components
# otherwise leaves fasls compiled against the old order, and the mixture shows
# up only at runtime -- once, as EPERM writing a child's setgroups, which looks
# like a kernel permission problem and is not.
# Built beside the binary and renamed into place, so an interrupted build leaves
# the previous scute rather than none at all.
scute: src/*.lisp *.asd
	@if [ ! -f .system-stamp ] || [ scute.asd -nt .system-stamp ]; then \
		echo "$(SBCL): scute.asd changed, recompiling everything"; \
		SCUTE_IMAGE_OUTPUT=$@.new $(SBCL) --eval "(asdf:make :scute :force t)" --quit; \
	else \
		SCUTE_IMAGE_OUTPUT=$@.new $(SBCL) --eval "(asdf:make :scute)" --quit; \
	fi
	@mv -f $@.new $@
	@cp scute.asd .system-stamp

completions: scute
	mkdir -p completions
	./scute completions bash > completions/scute.bash
	./scute completions zsh  > completions/_scute
	./scute completions fish > completions/scute.fish

man: scute
	mkdir -p man
	./scute man > man/scute.1

demo: scute
	@command -v vhs >/dev/null || \
		{ echo "vhs is not installed: https://github.com/charmbracelet/vhs"; exit 1; }
	cd docs && vhs demo.tape

# Rebuilding replaces the binary and loses its file capabilities, so granting
# them belongs with building rather than after it.  This is the thing to put in
# a build process that uses an address allowlist.
egress: scute
	releng/grant-capabilities.sh ./scute

sbom: scute-sbom.spdx.json

scute-sbom.spdx.json: ocicl.csv
	ocicl create-sbom spdx $@

# The sentinel is the point: a suite that dies partway through must not look
# like one that passed.  SBCL exits 0 on an unhandled SIGTERM.
test: scute
	rm -f .test-passed
	$(SBCL) --noinform --non-interactive \
		--eval '(asdf:test-system :scute)'
	@test -f .test-passed || { echo "the suite did not run to the end"; exit 1; }
	@rm -f .test-passed

smoke: scute
	releng/smoke.sh ./scute

check: test smoke

# Everything compiled from this tree, wherever ASDF put it.
clean-cache:
	rm -rf $(HOME)/.cache/common-lisp/*$(CURDIR)

clean: clean-cache
	rm -rf *~ scute scute.new scute-sbom.spdx.json completions man .system-stamp .test-passed

.PHONY: sbom completions man demo egress test smoke check clean clean-cache
