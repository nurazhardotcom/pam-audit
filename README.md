# pam-audit-clj

> **Status:** Active — maintained. Synthetic fixtures only, no real estates. See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

> **Portfolio lab — not a production CyberArk integration.** Mock SCIM/OAuth2 API only; no CyberArk affiliation, no customer data.

[![CI](https://github.com/nurazhardotcom/pam-audit-clj/actions/workflows/ci.yml/badge.svg)](https://github.com/nurazhardotcom/pam-audit-clj/actions)

> **Enterprise IAM/PAM & Policy-as-Code audit component.**
> Enforces least-privilege access, automated compliance checks, and
> privileged session governance for cloud and enterprise directory platforms.

* **Target environment:** Enterprise hybrid / vault-managed PAM and Active
  Directory (a SCIM-shaped mock API is built in; native CLI adapters can target
  a SCIM/OAuth2 endpoint).
* **Regulatory focus:** SG PDPA compliance-as-code.
* **Core function:** deterministic, version-controlled audit evaluation with
  caller-supplied time (`src/pam_audit/rules.cljc` — pure, no I/O).

The native CLI runs on Babashka without a project dependency install. It can
audit its deterministic mock API or a native SCIM/OAuth2 endpoint and emits
EDN/JSON reports covering orphaned privileged accounts, dormant privilege,
un-vaulted accounts, missing MFA, stale tokens, and never-logged-in privileged
accounts.

> **Scope, stated plainly:** the built-in server is a shape-compatible mock,
> not a real PAM product. The portable Clojure/ClojureScript core is exercised
> on the JVM and Node; the HTTP/OAuth/server/CLI adapters remain native. No
> browser HTTP, CORS, asynchronous transport, React, Shadow-cljs, or
> native-image parity is claimed here.

## Native CLI

Only `bb` is required for the native path:

```bash
bb test                              # 25 tests / 118 assertions
bb audit-demo                        # deterministic audit; exactly 5 findings
bb -m pam-audit.main audit --mock --format json
bb -m pam-audit.main audit --idsvc # audit sibling ../idsvc via /inventory
bb -m pam-audit.main mock-server --port 8899
bb check-native                      # native-image presence/readiness report
```

Live API through the native adapter:

```bash
bb -m pam-audit.main audit --base-url https://pam.example \
  --token-url https://pam.example/oauth2/token \
  --client-id LAB --client-secret '...' --format json
# or: --api-token '...' instead of the client-credentials trio
```

## Portable-core verification

The optional parity toolchain uses the versions pinned in `deps.edn`:
Clojure `1.12.6` and ClojureScript `1.12.145`. It adds no dependency to the
Babashka path.

```bash
clojure -M:test                       # 22 tests / 107 assertions on the JVM
clojure -M:test-cljs                  # compile the shared suite for Node
node target/cljs-tests.js             # 22 tests / 107 assertions in CLJS
clj-kondo --lint src test --fail-level warning
```

The JVM and CLJS runs load the same `rules_test.cljc`, `policy_test.cljc`, and
`portable_test.cljc` contract. `integration_test.clj` intentionally remains a
Babashka/JVM test because it starts a socket server and performs real local
HTTP.

## Layout

Portable shared source:

- `src/pam_audit/rules.cljc` — six-rule engine; `(audit-users estate now)`
  returns an ordered finding vector. Callers pass the clock.
- `src/pam_audit/policy.cljc` — MFA, assurance, and device-posture evaluation.
- `src/pam_audit/fixture.cljc` — canonical deterministic normalized EDN estate.
- `src/pam_audit/wire.cljc` — pure normalized-to-camelCase conversions.
- `src/pam_audit/normalize.cljc` — pure wire/local normalization.
- `src/pam_audit/idsvc_core.cljc` — pure idsvc inventory-to-estate translation.

Native adapters:

- `src/pam_audit/auth.clj` — OAuth2 client credentials or static API token.
- `src/pam_audit/scim.clj` — HTTP fetch plus compatibility aliases for the
  public `normalize-*` vars.
- `src/pam_audit/mock.clj` — socket server plus compatibility aliases for
  `now-fixture` and `estate-fixture`.
- `src/pam_audit/idsvc.clj` — inventory HTTP plus the `->estate` compatibility
  alias.
- `src/pam_audit/main.clj` — unchanged native CLI entry point and commands.

## Executable contract

The fixture produces exactly these five findings, in this order:

| # | Rule | Severity | Subject |
|---|---|---|---|
| 1 | `orphaned-privileged` | high | `svc-orphan` — no human owner |
| 2 | `inactive-privileged` | medium | `svc-dormant` — 120d dormant |
| 3 | `unvaulted-privileged` | high | `svc-unvaulted` — not vault-managed |
| 4 | `missing-mfa` | medium | `analyst-nomfa` — no MFA |
| 5 | `stale-token` | medium | `tok-stale` — 200d old, 180d TTL |

The sixth rule, `never-logged-in-privileged` (high), is exercised by a
synthetic privileged account. The shared contract freezes all six rule names,
severities, subjects, finding order, strict age boundaries, owner kinds,
fail-closed token behavior, wire normalization, and idsvc translation.

## Fidelity boundaries

- **Shared CLJC:** pure rules, policy evaluation, fixture loading, wire-shape
  conversion, normalization, and idsvc translation pass the same executable
  contract on the JVM and ClojureScript/Node.
- **Native original:** Babashka HTTP, OAuth2, JSON formatting, server sockets,
  clock reads, CLI behavior, and process checks are tested only in the native
  path.
- **Not claimed:** browser networking or HTTP parity, a browser CLI, real
  SCIM/OAuth behavior in CLJS, React/Shadow UI execution, or native-image
  compilation/result parity.

## Native binary status

A standalone GraalVM `native-image` binary remains deferred. Babashka already
provides the maintained native CLI distribution. `bb check-native` only reports
whether a `native-image` executable is present; it is not a build, smoke test,
or parity gate, and this repository does not claim Cheshire/HTTP native-image
compatibility without a future real build-and-test gate.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on pushes to
`main` and pull requests. Its gates are:

1. `bb test` and `bb audit-demo` for native CLI + HTTP integration;
2. the shared contract on pinned Clojure JVM and Node-targeted ClojureScript;
3. clj-kondo over `.clj`, `.cljc`, `.cljs`, and test sources; and
4. the existing synthetic PII/secret scan.

## License

MIT — see [LICENSE](LICENSE).
