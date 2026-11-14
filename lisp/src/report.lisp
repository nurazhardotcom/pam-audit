;;;; report.lisp --- Deterministic JSON / EDN / S-expression report emitters
;;;; and the process exit-code contract.
;;;;
;;;; Exit codes (fail closed):
;;;;   0  clean: zero findings
;;;;   1  audit finding: at least one finding
;;;;   2  usage or runtime error

(in-package #:pam-audit.report)

(defparameter +exit-clean+ 0)
(defparameter +exit-findings+ 1)
(defparameter +exit-usage+ 2)

(defun build-report (estate now &key source idsvc-url)
  "Run the rule engine and wrap findings in the deterministic report map.
SOURCE (when supplied) is copied to :SOURCE; IDSVC-URL to :IDSVC-URL."
  (let ((findings (pam-audit.rules:audit-users estate now)))
    (let ((report (make-map :scanned-at now
                            :summary (pam-audit.rules:summarize findings)
                            :findings findings)))
      (when source (map-set report :source source))
      (when idsvc-url (map-set report :idsvc-url idsvc-url))
      report)))

(defun report-string (report format)
  "Render REPORT as deterministic text in FORMAT: :json, :json-compact,
:edn (default) or :sexp."
  (case format
    (:json (format nil "~a~%" (pam-audit.json:stringify report :pretty t)))
    (:json-compact (format nil "~a~%" (pam-audit.json:stringify report)))
    (:sexp (format nil "~a~%" (pam-audit.edn:sexp-string report)))
    (t (format nil "~a~%" (pam-audit.edn:edn-string report)))))

(defun emit-report (report format &optional (stream *standard-output*))
  (write-string (report-string report format) stream)
  (finish-output stream)
  report)

(defun findings-exit-code (report)
  "0 when the report has no findings, 1 when it has at least one."
  (if (zerop (map-get (map-get report :summary) :total))
      +exit-clean+
      +exit-findings+))
