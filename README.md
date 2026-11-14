# pam-audit
Pure zero-dependency Common Lisp (SBCL) privileged-access audit CLI.
One runtime: SBCL 2.4+. Zero third-party Lisp libraries.
## Quick start
```bash
sbcl --version
./scripts/test.sh
XDG_DATA_DIRS="/usr/local/share:/usr/share" sbcl --no-userinit --script lisp/build.lisp
./bin/pam-audit --help
./bin/pam-audit audit --mock --format json
./scripts/verify.sh
```
## CLI
```bash
bin/pam-audit audit --mock [--format edn|json|sexp]
bin/pam-audit audit --base-url URL (--api-token T | --token-url U --client-id I --client-secret S)
bin/pam-audit audit --idsvc [--idsvc-url http://127.0.0.1:8081]
bin/pam-audit mock-server [--port 8899]
bin/pam-audit check-native
bin/pam-audit --help | --version
```
Exit codes: 0 clean, 1 findings, 2 usage or runtime error.
Live https uses curl transport; http uses sb-bsd-sockets.
## Rules
Six deterministic rules: orphaned-privileged (high), inactive-privileged (medium), never-logged-in-privileged (high), unvaulted-privileged (high), missing-mfa, stale-token (medium, fail-closed).
Mock estate yields five findings in fixed order. Thresholds are strict >.
## Layout
lisp/pam-audit.asd, lisp/build.lisp, lisp/src/, lisp/test/, scripts/, Makefile
## License
MIT - see LICENSE.
