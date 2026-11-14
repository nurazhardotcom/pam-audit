;;;; cli.lisp --- Command-line entry point and argument parser.
;;;;
;;;; Usage:
;;;;   pam-audit audit --mock [--format edn|json|sexp]
;;;;   pam-audit audit --base-url URL (--api-token T
;;;;                                    | --token-url U --client-id I --client-secret S)
;;;;   pam-audit audit --idsvc [--idsvc-url http://127.0.0.1:8081]
;;;;   pam-audit mock-server [--port 8899]
;;;;   pam-audit check-native
;;;;   pam-audit --help | --version

(in-package #:pam-audit.cli)

(defparameter +exit-clean+ 0)
(defparameter +exit-findings+ 1)
(defparameter +exit-usage+ 2)

(defparameter +version+ "2.0.0-sbcl"
  "Version string for this pure Common Lisp port.")

(defun usage (&optional (stream *error-output*))
  "Print the usage summary and flush STREAM."
  (write-string
   (format nil "~{~a~%~}"
           (list
            "pam-audit — SCIM/OAuth2 privileged-access audit (pure Common Lisp, SBCL)"
            ""
            "Usage:"
            "  pam-audit audit --mock [--format edn|json|sexp]"
            "  pam-audit audit --base-url URL (--api-token T | --token-url U --client-id I --client-secret S)"
            "  pam-audit audit --idsvc [--idsvc-url http://127.0.0.1:8081]"
            "  pam-audit mock-server [--port 8899]"
            "  pam-audit check-native"
            "  pam-audit --help | --version"
            ""
            "Flags:"
            "  --mock              audit the built-in deterministic mock estate (fixed clock)"
            "  --idsvc             audit a sibling idsvc via its /inventory endpoint"
            "  --idsvc-url URL     idsvc base URL (default http://127.0.0.1:8081)"
            "  --base-url URL      audit a live SCIM/OAuth2 endpoint"
            "  --api-token TOKEN   static bearer token (ispSS-style)"
            "  --token-url URL     OAuth2 token endpoint (client-credentials grant)"
            "  --client-id ID      OAuth2 client id"
            "  --client-secret S   OAuth2 client secret"
            "  --scope SCOPE       optional OAuth2 scope"
            "  --format FMT        report format: edn (default), json, sexp (json-pretty alias)"
            "  --json              shorthand for --format json"
            "  --port N            mock-server port (default 8899)"
            "  --help / -h         show this help (exit 0)"
            "  --version           print version (exit 0)"
            ""
            "Exit codes: 0 clean (no findings), 1 audit findings, 2 usage or runtime error."
            "Report formats: json/sexp are machine-readable; edn is the default."
            ""))
   stream)
  (finish-output stream)
  (values))

(defun flag-p (argument)
  (starts-with-p "--" argument))

(defun parse-args (argv)
  "Parse ARGV (a list of strings) into an equal hash table of options.
Positional words select the command (:CMD).  A flag followed by a value
consumes it; a flag followed by another flag (or nothing) is boolean T.
Unknown words are ignored, matching the original SBCL parser."
  (let ((opts (make-map))
        (remaining argv))
    (loop while remaining
          do (let ((word (pop remaining)))
               (cond
                 ((string= word "audit") (map-set opts :cmd :audit))
                 ((string= word "mock-server") (map-set opts :cmd :mock-server))
                 ((string= word "check-native") (map-set opts :cmd :check-native))
                 ((or (string= word "--help") (string= word "-h"))
                  (map-set opts :help t))
                 ((string= word "--version") (map-set opts :version t))
                 ((flag-p word)
                  (let ((value (first remaining)))
                    (if (and value (not (flag-p value)))
                        (progn (pop remaining)
                               (map-set opts (intern (string-upcase (subseq word 2)) :keyword) value))
                        (map-set opts (intern (string-upcase (subseq word 2)) :keyword) t))))
                 (t nil))))
    opts))

(defun choose-format (opts)
  "Resolve --format / --json to a report format keyword; reject unknown
formats with a usage error (exit 2) instead of silently defaulting."
  (let ((raw (map-get opts :format)))
    (when (eq raw t)
      (app-error* "--format needs a value: edn, json, or sexp"))
    (cond
      ((map-get opts :json) :json)
      ((null raw) :edn)
      ((member raw '("edn") :test #'string=) :edn)
      ((member raw '("json" "json-pretty") :test #'string=) :json)
      ((string= raw "json-compact") :json-compact)
      ((string= raw "sexp") :sexp)
      (t (app-error* (format nil "unknown --format '~a' (expected edn, json, json-compact, or sexp)"
                             raw))))))

(defun require-value (opts key flag)
  "Fetch a string option, signalling a usage error when it is missing or
given boolean-style."
  (let ((value (map-get opts key)))
    (when (or (null value) (eq value t) (not (stringp value)) (blankp value))
      (app-error* (format nil "~a needs a non-empty value" flag)))
    value))

(defun run-audit (opts)
  "Execute the audit command; returns the process exit code."
  (let ((format (choose-format opts))
        (mock (map-get opts :mock))
        (idsvc (map-get opts :idsvc))
        (base-url (map-get opts :base-url)))
    (unless (or mock idsvc base-url)
      (app-error* "audit needs one of: --mock, --idsvc, or --base-url"))
    (let ((report
            (cond
               (mock
                (let ((server (pam-audit.mock:start-server :port 0)))
                  (unwind-protect
                       (let ((thread (sb-thread:make-thread
                                      (lambda () (pam-audit.mock:serve-forever server))
                                      :name "pam-audit-mock")))
                         (unwind-protect
                              (pam-audit.report:build-report
                               (pam-audit.scim:fetch-estate (pam-audit.mock:server-base-url server)
                                                            "mock-token-123")
                               (pam-audit.fixture:now-fixture)
                               :source :mock)
                           (pam-audit.mock:stop-server server)
                           (ignore-errors (sb-thread:join-thread thread :timeout 5))
                           (when (sb-thread:thread-alive-p thread)
                             (ignore-errors (sb-thread:terminate-thread thread)))))
                    (pam-audit.mock:stop-server server))))
              (idsvc
               (let* ((url (or (map-get opts :idsvc-url) "http://127.0.0.1:8081"))
                      (inventory (pam-audit.idsvc:fetch-inventory url)))
                 (pam-audit.report:build-report
                  (pam-audit.idsvc:inventory->estate inventory)
                  (current-epoch)
                  :source :idsvc
                  :idsvc-url url)))
              (t
               (let* ((token (or (map-get opts :api-token)
                                 (pam-audit.auth:resolve-token
                                  (make-map :token-url (map-get opts :token-url)
                                            :client-id (map-get opts :client-id)
                                            :client-secret (map-get opts :client-secret)
                                            :scope (map-get opts :scope)))))
                      (url (require-value opts :base-url "--base-url")))
                 (pam-audit.report:build-report
                  (pam-audit.scim:fetch-estate url token)
                  (current-epoch)
                  :source url))))))
      (pam-audit.report:emit-report report format)
      (pam-audit.report:findings-exit-code report))))

(defun run-mock-server (opts)
  "Start the mock API and serve until interrupted.  Never returns normally."
  (let* ((raw-port (map-get opts :port))
         (port (cond
                 ((null raw-port) 8899)
                 ((eq raw-port t) 8899)
                 ((parse-integer-or-nil raw-port) (parse-integer-or-nil raw-port))
                 (t (app-error* (format nil "--port expects an integer, got '~a'" raw-port)))))
         (server (pam-audit.mock:start-server :port port)))
    (format *standard-output* "mock PAM API on ~a (Ctrl-C to stop)~%"
            (pam-audit.mock:server-base-url server))
    (finish-output *standard-output*)
    (unwind-protect
         (pam-audit.mock:serve-forever server)
      (pam-audit.mock:stop-server server))
    +exit-clean+))

(defun check-native ()
  "Report the runtime this binary was built on plus native-image readiness."
  (let ((data (make-map :sbcl (lisp-implementation-version)
                        :implementation (string-downcase (lisp-implementation-type))
                        :native-image :false
                        :dependency-free t
                        :note "standalone SBCL binary; no GraalVM native-image required")))
    (pam-audit.edn:write-edn data *standard-output*)
    +exit-clean+))

(defun main (argv)
  "Entry point taking a list of argument strings; returns the exit code.
A usage or runtime error is reported on stderr and yields exit code 2."
  (handler-case
      (let ((opts (parse-args argv)))
        (cond
          ((map-get opts :help) (usage *standard-output*) +exit-clean+)
          ((map-get opts :version)
           (format t "pam-audit ~a (SBCL ~a)~%" +version+ (lisp-implementation-version))
           +exit-clean+)
          (t
           (case (map-get opts :cmd)
             (:audit (run-audit opts))
             (:mock-server (run-mock-server opts))
             (:check-native (check-native))
             (t (usage *error-output*) +exit-usage+)))))
    (pam-audit.conditions:app-error (condition)
      (format *error-output* "pam-audit: ~a~%" (pam-audit.conditions:app-error-message condition))
      (let ((detail (pam-audit.conditions:app-error-detail condition)))
        (when detail
          (format *error-output* "pam-audit: detail ~s~%" detail)))
      +exit-usage+)
    (error (condition)
      (format *error-output* "pam-audit: internal error: ~a~%" condition)
      +exit-usage+)))
