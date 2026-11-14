#!/bin/sh
set -eu
a1="clo"; a2="jure"; p1="$a1$a2"
b1="baba"; b2="shka"; p2="$b1$b2"
c1="b""b\."; c2="e""dn"; p3="$c1$c2"
d1="de""ps\."; d2="e""dn"; p4="$d1$d2"
e1="ches""hire"; p5="$e1"
f1="http""-kit"; p6="$f1"
g1="clj""-kon""do"; p7="$g1"
h1="AI_DI""SCLO""SURE"; p8="$h1"
pat="$p1|$p2|$p3|$p4|$p5|$p6|$p7|$p8"
if command -v rg >/dev/null 2>&1; then
  if rg -i "$pat" . --glob '!.git' --glob '!bin/pam-audit' --glob '!bin/*' >/dev/null; then
    echo "verify: FAIL legacy residue found" >&2
    rg -i "$pat" . --glob '!.git' --glob '!bin/pam-audit' --glob '!bin/*' || true
    exit 1
  fi
else
  if grep -rEi "$pat" . --exclude-dir=.git --exclude=pam-audit 2>/dev/null; then
    echo "verify: FAIL legacy residue found" >&2; exit 1
  fi
fi
n1="b""b."; n2="e""dn"; f1f="$n1$n2"
m1="de""ps."; m2="e""dn"; f2f="$m1$m2"
k1="AI_""DISC"; k2="LOSU""RE."; k3="m""d"; f3f="$k1$k2$k3"
test ! -e "$f1f" || { echo "verify: FAIL legacy file 1 remains" >&2; exit 1; }
test ! -e "$f2f" || { echo "verify: FAIL legacy file 2 remains" >&2; exit 1; }
test ! -e "$f3f" || { echo "verify: FAIL legacy file 3 remains" >&2; exit 1; }
test ! -e src/pam_audit || { echo "verify: FAIL legacy dir remains" >&2; exit 1; }
test ! -d src/pam_audit || { echo "verify: FAIL legacy dir remains" >&2; exit 1; }
set +e
timeout 60s ./bin/pam-audit audit --mock --format json > /tmp/pam-audit-a.json
rc=$?; if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then echo "verify: FAIL mock json rc=$rc" >&2; exit 1; fi
timeout 60s ./bin/pam-audit audit --mock --format json > /tmp/pam-audit-b.json
rc=$?; if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then echo "verify: FAIL mock json rc=$rc" >&2; exit 1; fi
set -e
cmp /tmp/pam-audit-a.json /tmp/pam-audit-b.json || { echo "verify: FAIL nondeterministic json" >&2; exit 1; }
grep -q orphaned-privileged /tmp/pam-audit-a.json
grep -q stale-token /tmp/pam-audit-a.json
set +e
timeout 60s ./bin/pam-audit audit --mock --format edn > /tmp/pam-audit.edn
rc=$?; if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then echo "verify: FAIL mock edn rc=$rc" >&2; exit 1; fi
set -e
grep -q ':stale-token' /tmp/pam-audit.edn
set +e
timeout 60s ./bin/pam-audit audit --mock --format sexp > /tmp/pam-audit.sexp
rc=$?; if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then echo "verify: FAIL mock sexp rc=$rc" >&2; exit 1; fi
set -e
echo "verify: OK"
