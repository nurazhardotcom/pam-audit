;;;; runner.lisp --- Suite runner used by ASDF TEST-OP.
;;;;
;;;;   sbcl --eval '(require :asdf)' --eval '(asdf:test-system "pam-audit")'
;;;;
;;;; RUN executes every registered deftest in definition order and returns T
;;;; only when every assertion passed.  A script entry point is provided for
;;;; `sbcl --script t/run-tests.lisp` style invocation from a loaded system.

(in-package #:pam-audit.tests)

(defun run-all ()
  (run))

;; The test system's :PERFORM calls PAM-AUDIT.TESTS:RUN.  Keep that entry
;; point side-effect free apart from output so ASDF decides pass/fail.
