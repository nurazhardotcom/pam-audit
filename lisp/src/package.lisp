;;;; package.lisp --- Package definitions for pam-audit.
;;;;
;;;; Pure Common Lisp (SBCL).  Zero Quicklisp/third-party dependencies.
;;;; The JSON package (PAM-AUDIT.JSON) is defined by src/json.lisp itself.

(defpackage #:pam-audit.conditions
  (:use #:cl)
  (:export #:app-error
           #:app-error-message
           #:app-error-detail
           #:app-error*))

(defpackage #:pam-audit.util
  (:use #:cl)
  (:export #:trim
           #:blankp
           #:clj-str
           #:keyword-name
           #:string-join
           #:starts-with-p
           #:ends-with-p
           #:replace-all
           #:truthy
           #:boolean-value
           #:equivp
           #:+json-null+
           #:null-value
           #:make-map
           #:map-get
           #:map-get-any
           #:map-has-p
           #:map-has-any-p
           #:map-set
           #:copy-map
           #:map-keys
           #:map-values
           #:map-remove
           #:merge-maps
           #:keywordize
           #:key-name
           #:key-string=
           #:keys-equal-p
           #:sorted-keys
           #:split-string
           #:parse-integer-or-nil
           #:current-epoch
           #:make-set
           #:set-member-p
           #:set-add
           #:map-equal))

(defpackage #:pam-audit.edn
  (:use #:cl #:pam-audit.util)
  (:export #:edn-string
           #:sexp-string
           #:write-edn
           #:write-sexp))

(defpackage #:pam-audit.http
  (:use #:cl #:pam-audit.util #:pam-audit.conditions)
  (:export #:response
           #:response-status
           #:response-body
           #:response-headers
           #:make-response
           #:request
           #:http-get
           #:http-post
           #:base64-encode-string
           #:url-encode
           #:parse-url))

(defpackage #:pam-audit.fixture
  (:use #:cl #:pam-audit.util)
  (:export #:+seconds-per-day+
           #:+now-fixture+
           #:now-fixture
           #:days-ago
           #:estate-fixture
           #:inventory-fixture))

(defpackage #:pam-audit.wire
  (:use #:cl #:pam-audit.util)
  (:export #:user->wire
           #:token->wire
           #:policy->wire))

(defpackage #:pam-audit.normalize
  (:use #:cl #:pam-audit.util)
  (:export #:normalize-user
           #:normalize-group
           #:normalize-token
           #:normalize-policy))

(defpackage #:pam-audit.policy
  (:use #:cl #:pam-audit.util)
  (:export #:assurance-rank
           #:assurance-position
           #:meets-assurance-p
           #:evaluate-user
           #:evaluate-all))

(defpackage #:pam-audit.rules
  (:use #:cl #:pam-audit.util)
  (:export #:+seconds-per-day+
           #:days-between
           #:privileged-member-ids
           #:orphaned-privileged
           #:inactive-privileged
           #:never-logged-in-privileged
           #:unvaulted-privileged
           #:missing-mfa
           #:stale-token
           #:audit-users
           #:summarize))

(defpackage #:pam-audit.scim
  (:use #:cl #:pam-audit.util #:pam-audit.conditions)
  (:export #:get-json
           #:fetch-estate))

(defpackage #:pam-audit.idsvc
  (:use #:cl #:pam-audit.util #:pam-audit.conditions)
  (:export #:inventory->estate
           #:fetch-inventory))

(defpackage #:pam-audit.auth
  (:use #:cl #:pam-audit.util #:pam-audit.conditions)
  (:export #:basic-auth
           #:client-credentials-token
           #:resolve-token))

(defpackage #:pam-audit.mock
  (:use #:cl #:pam-audit.util #:pam-audit.conditions)
  (:export #:start-server
           #:stop-server
           #:serve-forever
           #:server-base-url
           #:server-port
           #:routes))

(defpackage #:pam-audit.report
  (:use #:cl #:pam-audit.util)
  (:export #:build-report
           #:emit-report
           #:report-string
           #:findings-exit-code))

(defpackage #:pam-audit.cli
  (:use #:cl #:pam-audit.util #:pam-audit.conditions)
  (:export #:main
           #:usage
           #:parse-args
           #:+exit-clean+
           #:+exit-findings+
           #:+exit-usage+))

(defpackage #:pam-audit.core
  (:use #:cl)
  (:export #:main
           #:entry
           #:usage
           #:standalone-p
           #:*standalone-p*))
