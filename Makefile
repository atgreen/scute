# SBCL is overridable because the binary inherits its toolchain: a Lisp
# installed under a private prefix produces an executable that will not run
# where that prefix is absent.  releng/smoke.sh says so if it happens.
SBCL ?= sbcl

scute: src/*.lisp *.asd
	$(SBCL) --eval "(asdf:make :scute)" --quit

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

clean:
	rm -rf *~ scute scute-sbom.spdx.json completions man

.PHONY: sbom completions man demo test smoke check clean
