;;;; rules-test.lisp --- Rule engine contract tests.

(in-package #:pam-audit.tests)

(defun estate ()
  (pam-audit.fixture:estate-fixture))

(defun now ()
  (pam-audit.fixture:now-fixture))

(defun select (predicate sequence)
  (coerce (loop for item across sequence
                when (funcall predicate item)
                  collect item)
          'vector))

(defun flagged-set (findings)
  (let ((set (make-hash-table :test #'equal)))
    (loop for finding across findings
          do (setf (gethash (or (map-get finding :user) (map-get finding :subject)) set) t))
    set))

(defun by-rule (findings rule)
  (select (lambda (finding) (eq (map-get finding :rule) rule)) findings))

(defun rule-set (findings)
  (let ((table (make-hash-table :test #'eq)))
    (loop for finding across findings
          do (setf (gethash (map-get finding :rule) table) t))
    table))

(deftest test-fixture-yields-exactly-five-findings
  (let ((findings (pam-audit.rules:audit-users (estate) (now))))
    (is (= 5 (length findings)) "total")
    (is (= 5 (hash-table-count (rule-set findings))) "five distinct rules")
    (is (not (null (pam-audit.util:set-member-p (rule-set findings) :orphaned-privileged))))
    (dolist (rule '(:orphaned-privileged :inactive-privileged
                    :unvaulted-privileged :missing-mfa :stale-token))
      (is (= 1 (length (by-rule findings rule)))
          (format nil "expected exactly 1 ~a" rule)))
    (is (equal "svc-orphan" (map-get (aref (by-rule findings :orphaned-privileged) 0) :user)))
    (is (eq :high (map-get (aref (by-rule findings :orphaned-privileged) 0) :severity)))
    (is (equal "svc-dormant" (map-get (aref (by-rule findings :inactive-privileged) 0) :user)))
    (is (equal "svc-unvaulted" (map-get (aref (by-rule findings :unvaulted-privileged) 0) :user)))
    (is (equal "analyst-nomfa" (map-get (aref (by-rule findings :missing-mfa) 0) :user)))
    (is (eq :medium (map-get (aref (by-rule findings :missing-mfa) 0) :severity)))
    (is (equal "tok-stale"
               (map-get (map-get (aref (by-rule findings :stale-token) 0) :evidence)
                        :token-id)))
    (is (equal "svc-dormant" (map-get (aref (by-rule findings :stale-token) 0) :subject)))))

(deftest test-clean-accounts-produce-no-findings
  (let* ((findings (pam-audit.rules:audit-users (estate) (now)))
         (flagged (flagged-set findings)))
    (is (not (pam-audit.util:set-member-p flagged "ciso")))
    (is (not (pam-audit.util:set-member-p flagged "admin-active")))))

(deftest test-summarize
  (let ((summary (pam-audit.rules:summarize (pam-audit.rules:audit-users (estate) (now)))))
    (is (= 5 (map-get summary :total)))
    (is (= 2 (map-get (map-get summary :by-severity) :high)))
    (is (= 3 (map-get (map-get summary :by-severity) :medium)))
    (is (pam-audit.util:map-equal
         (make-map :inactive-privileged 1 :missing-mfa 1 :orphaned-privileged 1
                   :stale-token 1 :unvaulted-privileged 1)
         (map-get summary :by-rule))
        "by-rule counts")))

(deftest test-revoked-tokens-are-ignored
  (let ((estate (estate)))
    (map-set estate :tokens
             (concatenate 'vector
                          (map-get estate :tokens)
                          (vector (make-map :id "tok-revoked-old" :owner-id "ciso"
                                            :created (- (now) (* 400 86400))
                                            :revoked t))))
    (is (= 5 (length (pam-audit.rules:audit-users estate (now)))))))

(deftest test-empty-estate-is-clean
  (is (= 0 (length (pam-audit.rules:audit-users
                    (make-map :users (vector) :groups (vector) :tokens (vector)
                              :policies (map-get (estate) :policies))
                    (now))))))

(defun add-ghost (estate)
  (map-set estate :users
           (concatenate 'vector
                        (map-get estate :users)
                        (vector (make-map :id "svc-ghost" :kind :service
                                          :active t :owner-id "ciso"
                                          :mfa-enrolled t :assurance :mfa
                                          :vault-managed t :device-compliant t))))
  (map-set estate :groups
           (map 'vector
                (lambda (group)
                  (if (equal "vault-admins" (map-get group :id))
                      (let ((copy (copy-map group)))
                        (map-set copy :members
                                 (concatenate 'vector (map-get group :members)
                                              (vector "svc-ghost")))
                        copy)
                      group))
                (map-get estate :groups)))
  estate)

(deftest test-never-logged-in-privileged-is-flagged
  (let* ((findings (pam-audit.rules:audit-users (add-ghost (estate)) (now)))
         (ghost (select (lambda (f) (equal "svc-ghost" (map-get f :user))) findings)))
    (is (= 6 (length findings)))
    (is (= 1 (length ghost)))
    (is (eq :never-logged-in-privileged (map-get (aref ghost 0) :rule)))
    (is (eq :high (map-get (aref ghost 0) :severity)))))

(deftest test-token-without-created-is-flagged
  (let ((estate (estate)))
    (map-set estate :tokens
             (concatenate 'vector
                          (map-get estate :tokens)
                          (vector (make-map :id "tok-nodate" :owner-id "ciso"
                                            :revoked :false))))
    (let* ((findings (pam-audit.rules:audit-users estate (now)))
           (suspect (remove-if-not
                     (lambda (f)
                       (equal "tok-nodate" (map-get (map-get f :evidence) :token-id)))
                     findings)))
      (is (= 6 (length findings)))
      (is (= 1 (length suspect)))
      (is (eq :stale-token (map-get (aref suspect 0) :rule)))
      (is (null (map-get (map-get (aref suspect 0) :evidence) :age-days))))))

(deftest test-owner-kind-normalization
  (is (null (pam-audit.rules:orphaned-privileged
             (make-map :id "x" :is-privileged t :owner-id "o")
             (make-map "o" (make-map :kind "human" :active t))
             (now))))
  (is (null (pam-audit.rules:orphaned-privileged
             (make-map :id "x" :is-privileged t :owner-id "o")
             (make-map "o" (make-map :kind :human :active t))
             (now))))
  (is (eq :not-human
          (map-get (map-get (pam-audit.rules:orphaned-privileged
                             (make-map :id "x" :is-privileged t :owner-id "o")
                             (make-map "o" (make-map :kind "service" :active t))
                             (now))
                            :evidence)
                   :owner-state))))
