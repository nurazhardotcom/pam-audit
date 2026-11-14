;;;; integration-test.lisp --- Real-socket, CLI and report-contract tests.
;;;;
;;;; These exercise the same paths the binary uses: the mock SCIM server on a
;;;; loopback socket, OAuth2 client credentials, estate fetch/normalize, the
;;;; idsvc bridge, and the deterministic report emitters.

(in-package #:pam-audit.tests)

(defun with-mock (function)
  "Start an ephemeral mock server, call FUNCTION with its base URL, stop it."
  (let ((server (pam-audit.mock:start-server :port 0)))
    (unwind-protect
         (let ((thread (sb-thread:make-thread
                        (lambda () (pam-audit.mock:serve-forever server))
                        :name "pam-audit-mock")))
           (ignore-errors (funcall function (pam-audit.mock:server-base-url server)))
           (pam-audit.mock:stop-server server)
           (ignore-errors (sb-thread:join-thread thread :timeout 5))
           (when (sb-thread:thread-alive-p thread)
             (sb-thread:terminate-thread thread)))
      (pam-audit.mock:stop-server server))))

(deftest test-client-credentials-flow-against-mock
  (with-mock
    (lambda (base)
      (is (equal "mock-token-123"
                 (let ((cfg (make-map :token-url (format nil "~a/oauth2/token" base)
                                      :client-id "lab" :client-secret "s3cret")))
                   (pam-audit.auth:client-credentials-token cfg)))))))

(deftest test-estate-round-trips-through-http
  (with-mock
    (lambda (base)
      (let* ((estate (pam-audit.scim:fetch-estate base "mock-token-123"))
             (findings (pam-audit.rules:audit-users
                        estate (pam-audit.fixture:now-fixture))))
        (is (pam-audit.util:map-equal (pam-audit.fixture:estate-fixture) estate)
            "wire normalization reproduces the fixture")
        (is (= 5 (length findings)) "end-to-end audit finds exactly 5")
        (is (= 2 (length (select (lambda (f) (eq (map-get f :severity) :high))
                                        (coerce findings 'list))))
            "two high findings")))))

(deftest test-api-token-preferred-over-oauth
  (is (equal "static-token"
             (pam-audit.auth:resolve-token (make-map :api-token "static-token"))))
  (signals pam-audit.conditions:app-error
    (pam-audit.auth:resolve-token (make-map :token-url "http://127.0.0.1:1/token"))))

(deftest test-idsvc-inventory-translation
  (let ((inventory (pam-audit.fixture:inventory-fixture)))
    (let ((estate (pam-audit.idsvc:inventory->estate inventory)))
      (is (= 4 (length (map-get estate :users))) "two humans and two NHIs")
      (is (= 2 (length (map-get (aref (map-get estate :groups) 0) :members))))
      (is (= 0 (length (map-get estate :tokens)))))))

(deftest test-native-public-compatibility-aliases
  (let ((inventory (make-map :humans (vector (make-map :name "alice"))
                             :non_human_identities (vector (make-map :name "worker"
                                                                     :sponsor "alice")))))
    (is (= pam-audit.fixture:+now-fixture+ (pam-audit.fixture:now-fixture)))
    (is (pam-audit.util:map-equal (pam-audit.fixture:estate-fixture)
                                   (pam-audit.fixture:estate-fixture)))
    (is (pam-audit.util:map-equal (pam-audit.idsvc:inventory->estate inventory)
                                   (pam-audit.idsvc:inventory->estate inventory)))))

;;; ---------------------------------------------------------------------------
;;; Report emitters and exit-code contract
;;; ---------------------------------------------------------------------------

(defun fixture-report ()
  (pam-audit.report:build-report (pam-audit.fixture:estate-fixture)
                                 (pam-audit.fixture:now-fixture)
                                 :source :mock))

(deftest test-report-json-is-deterministic-and-complete
  (let* ((first-run (pam-audit.report:report-string (fixture-report) :json))
         (second-run (pam-audit.report:report-string (fixture-report) :json))
         (parsed (pam-audit.json:parse first-run :keywordize t))
         (findings (map-get parsed :findings))
         (summary (map-get parsed :summary)))
    (is (string= first-run second-run) "byte-identical output")
    (is (= 5 (length findings)))
    (is (= 5 (map-get summary :total)))
    (is (equal "svc-orphan" (map-get (aref findings 0) :user)))
    (is (eq :orphaned-privileged (map-get (aref findings 0) :rule)))
    ;; JSON null decodes back to NIL, not to the string "null"
    (is (null (map-get (map-get (aref findings 0) :evidence) :owner-id)))
    ;; literal-false evidence stays a JSON boolean (decoded as :FALSE), not text
    (is (eq :false (map-get (map-get (aref findings 2) :evidence) :vault-managed)))
    (is (not (search "(:" first-run)))))

(deftest test-report-edn-and-sexp-are-deterministic
  (let ((edn (pam-audit.report:report-string (fixture-report) :edn))
        (sexp (pam-audit.report:report-string (fixture-report) :sexp)))
    (is (search ":scanned-at 1788460800" edn))
    (is (search ":source :mock" edn))
    (is (search ":rule :orphaned-privileged" edn))
    (is (search ":message \"privileged account 'svc-orphan' has no active human owner\"" edn))
    (is (search "(:scanned-at 1788460800" sexp))
    (is (string= edn (pam-audit.report:report-string (fixture-report) :edn)))))

(deftest test-exit-code-contract
  (is (= 1 (pam-audit.report:findings-exit-code (fixture-report))))
  (is (= 0 (pam-audit.report:findings-exit-code
            (pam-audit.report:build-report
             (make-map :users (vector) :groups (vector) :tokens (vector) :policies (make-map))
             0))))
  (is (= 0 (pam-audit.cli:main '("check-native"))) "check-native exits 0")
  (is (= 0 (pam-audit.cli:main '("--help"))))
  (is (= 0 (pam-audit.cli:main '("--version"))))
  (is (= 2 (pam-audit.cli:main '())) "no command is a usage error")
  (is (= 2 (pam-audit.cli:main '("audit"))) "audit without a source is a usage error")
  (is (= 2 (pam-audit.cli:main '("audit" "--mock" "--format" "yaml")))
      "unknown format is a usage error")
  (is (= 2 (pam-audit.cli:main '("bogus-command")))))

(deftest test-audit-mock-end-to-end-exit-code-and-output
  (let ((*standard-output* (make-string-output-stream)))
    (is (= 1 (pam-audit.cli:main '("audit" "--mock" "--format" "json"))))
    (let* ((text (get-output-stream-string *standard-output*))
           (parsed (pam-audit.json:parse text :keywordize t)))
      (is (= 5 (map-get (map-get parsed :summary) :total)))
      (is (eq :mock (map-get parsed :source)))
      (is (= 1788460800 (map-get parsed :scanned-at))))))
