# pam-audit architecture
Pure SBCL. Zero third-party Lisp libraries.
## Components
- lisp/src/package.lisp: package definitions
- lisp/src/json.lisp: deterministic sorted-key JSON parser and emitter
- lisp/src/edn.lisp: deterministic EDN and S-expression emitters
- lisp/src/http.lisp: http via sb-bsd-sockets; https via curl; POST inputs use (make-string-input-stream body)
- lisp/src/conditions.lisp, util.lisp, fixture.lisp, wire.lisp, normalize.lisp
- lisp/src/policy.lisp, rules.lisp (six-rule engine), auth.lisp, scim.lisp, idsvc.lisp, mock.lisp, report.lisp, cli.lisp, core.lisp
## Data flow
mock | scim | idsvc -> normalize -> rules -> report -> json|edn|sexp -> stdout
Callers pass clock (now epoch seconds). Sorted keys keep runs byte-identical.
## Build
lisp/build.lisp strips non-absolute XDG_DATA_DIRS, loads lisp/pam-audit.asd, resolves toplevel via (find-symbol "ENTRY" "PAM-AUDIT.CORE"), dumps bin/pam-audit with :save-runtime-options t :executable t :compression t.
## Tests
lisp/test/ self-contained ANSI CL runner. Covers six rules, threshold edges, mock runs, formatting, determinism.
