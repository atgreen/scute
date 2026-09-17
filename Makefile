scute: src/*.lisp *.asd
	sbcl --eval "(asdf:make :scute)" --quit

sbom: scute-sbom.spdx.json

scute-sbom.spdx.json: ocicl.csv
	ocicl create-sbom spdx $@

test:
	sbcl --noinform --non-interactive \
		--eval '(asdf:test-system :scute)'

check: test

clean:
	rm -rf *~ scute scute-sbom.spdx.json

.PHONY: sbom test check clean
