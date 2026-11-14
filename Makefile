.PHONY: test build smoke verify clean
test: ; sbcl --no-userinit --non-interactive --disable-debugger --eval '(require :asdf)' --eval '(push (truename "lisp/") asdf:*central-registry*)' --eval '(setf asdf:*compile-file-warnings-behaviour* :error)' --eval '(asdf:load-system "pam-audit/tests" :force t)' --eval '(asdf:test-system "pam-audit")'
build: ; XDG_DATA_DIRS="/usr/local/share:/usr/share" sbcl --no-userinit --script lisp/build.lisp
smoke: build ; ./bin/pam-audit --help ; ./bin/pam-audit audit --mock --format json > /tmp/pam-audit-smoke.json || test $? -eq 1 ; grep -q orphaned-privileged /tmp/pam-audit-smoke.json
verify: test smoke ; ./scripts/verify.sh
clean: ; rm -rf bin/pam-audit bin/ .ci-smoke/
