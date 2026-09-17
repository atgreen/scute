scute: src/*.lisp *.asd
	sbcl --eval "(asdf:make :scute)" --quit

test:
	sbcl --noinform --non-interactive \
		--eval '(asdf:test-system :scute)'

check: test

clean:
	rm -rf *~ scute
