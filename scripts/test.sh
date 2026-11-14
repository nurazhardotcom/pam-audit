#!/bin/sh
set -eu
XDG_DATA_DIRS="/usr/local/share:/usr/share" sbcl --no-userinit --non-interactive --disable-debugger --eval '(require :asdf)' --eval '(push (truename "lisp/") asdf:*central-registry*)' --eval '(setf asdf:*compile-file-warnings-behaviour* :error)' --eval '(asdf:load-system "pam-audit/tests" :force t)' --eval '(asdf:test-system "pam-audit")'
