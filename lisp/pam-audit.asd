(asdf:defsystem "pam-audit"
  :description "Deterministic SCIM/OAuth2 privileged-access (PAM) audit CLI"
  :long-description "Unified IAM/PAM estate audit. Pure ANSI Common Lisp; deterministic EDN, JSON, S-expression reports. Exit codes: 0 clean, 1 findings, 2 usage/runtime."
  :version "0.2.0"
  :author "Nur Azhar"
  :licence "MIT"
  :serial t
  :depends-on ()
  :components ((:file "src/json")
               (:file "src/package")
               (:file "src/conditions")
               (:file "src/util")
               (:file "src/edn")
               (:file "src/fixture")
               (:file "src/wire")
               (:file "src/normalize")
               (:file "src/policy")
               (:file "src/rules")
               (:file "src/http")
               (:file "src/auth")
               (:file "src/scim")
               (:file "src/idsvc")
               (:file "src/mock")
               (:file "src/report")
               (:file "src/cli")
               (:file "src/core")))
(asdf:defsystem "pam-audit/tests"
  :description "Self-contained ANSI-CL test suite for pam-audit."
  :version "0.2.0"
  :licence "MIT"
  :serial t
  :depends-on ("pam-audit")
  :components ((:file "test/package")
               (:file "test/harness")
               (:file "test/rules-test")
               (:file "test/policy-test")
               (:file "test/portable-test")
               (:file "test/integration-test")
               (:file "test/runner"))
  :perform (test-op (o c) (uiop:symbol-call :pam-audit.tests :run)))
