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

# Packaging.
#
# The tarball carries the ocicl dependency tree, because a package build that
# fetched dependencies would be a package whose contents depend on the day it was
# built.  "ocicl install" first if ocicl/ is not there yet.
VERSION := $(shell sed -n 's/^  :version *"\(.*\)".*/\1/p' scute.asd)

rpm: scute
	@command -v rpmbuild >/dev/null || \
		{ echo "rpmbuild is not installed: dnf install rpm-build rpmdevtools"; exit 1; }
	@test -d ocicl || { echo "no vendored dependencies: run ocicl install"; exit 1; }
	rm -rf build/rpm build/src
	mkdir -p build/rpm/SOURCES build/rpm/SPECS build/src/scute-$(VERSION)
	tar --exclude=.git --exclude=build --exclude=.beads --exclude=scute \
	    --exclude='*~' --exclude='*.fasl' -cf - . \
	  | tar -xf - -C build/src/scute-$(VERSION)
	tar -czf build/rpm/SOURCES/scute-$(VERSION).tar.gz -C build/src scute-$(VERSION)
	cp releng/scute.spec build/rpm/SPECS/
	rpmbuild --define "_topdir $(CURDIR)/build/rpm" -bb build/rpm/SPECS/scute.spec
	@echo
	@echo "built: $$(ls $(CURDIR)/build/rpm/RPMS/*/*.rpm)"

# Installation.
#
# PREFIX defaults to /usr/local, which is where a build from source belongs.  For
# a copy of your own, without root:
#
#     make install PREFIX=$$HOME/.local
#
# The policies go to $(DESTDIR)$(PREFIX)/share/scute/policies, which is on the
# search path "scute run --policy NAME" uses -- so an installed policy is one you
# can run by name.  A policy of the same name in ~/.config/scute/policies wins
# over an installed one, which is how you edit one without an upgrade undoing it.
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(DATADIR)/man

install: scute completions man
	install -D -m 0755 scute $(DESTDIR)$(BINDIR)/scute
	install -D -m 0644 man/scute.1 $(DESTDIR)$(MANDIR)/man1/scute.1
	install -D -m 0644 completions/scute.bash \
		$(DESTDIR)$(DATADIR)/bash-completion/completions/scute
	install -D -m 0644 completions/_scute $(DESTDIR)$(DATADIR)/zsh/site-functions/_scute
	install -D -m 0644 completions/scute.fish \
		$(DESTDIR)$(DATADIR)/fish/vendor_completions.d/scute.fish
	for policy in policies/*.policy; do \
		install -D -m 0644 "$$policy" \
			"$(DESTDIR)$(DATADIR)/scute/policies/$$(basename $$policy)"; \
	done
	@echo
	@echo "Installed. Policies you can now run by name:"
	@for policy in policies/*.policy; do \
		echo "  scute run --policy $$(basename $$policy .policy) -- ..."; \
	done

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/scute $(DESTDIR)$(MANDIR)/man1/scute.1 \
		$(DESTDIR)$(DATADIR)/bash-completion/completions/scute \
		$(DESTDIR)$(DATADIR)/zsh/site-functions/_scute \
		$(DESTDIR)$(DATADIR)/fish/vendor_completions.d/scute.fish
	rm -rf $(DESTDIR)$(DATADIR)/scute/policies

# Everything compiled from this tree, wherever ASDF put it.
clean-cache:
	rm -rf $(HOME)/.cache/common-lisp/*$(CURDIR)

clean: clean-cache
	rm -rf *~ scute scute.new scute-sbom.spdx.json completions man .system-stamp .test-passed build

.PHONY: sbom completions man demo egress test smoke check clean clean-cache install uninstall rpm
