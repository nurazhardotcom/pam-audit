;;;; portable-test.lisp --- The frozen cross-platform contract: exact finding
;;;; vector, strict thresholds, owner normalization, assurance ranking, wire
;;;; round-trips, idsvc translation, and repair isolation.

(in-package #:pam-audit.tests)

(defparameter +day+ 86400)

(defun finding (rule severity &key user subject evidence message)
  (let ((map (make-map :rule rule :severity severity)))
    (when user (map-set map :user user))
    (when subject (map-set map :subject subject))
    (map-set map :evidence evidence)
    (map-set map :message message)
    map))

(defun expected-fixture-findings ()
  (vector
   (finding :orphaned-privileged :high
            :user "svc-orphan"
            :evidence (make-map :owner-id nil :owner-state :missing
                                :checked-at (pam-audit.fixture:now-fixture))
            :message "privileged account 'svc-orphan' has no active human owner")
   (finding :inactive-privileged :medium
            :user "svc-dormant"
            :evidence (make-map :last-login 1778092800 :dormant-days 120
                                :threshold-days 90)
            :message "privileged account 'svc-dormant' dormant beyond 90 days")
   (finding :unvaulted-privileged :high
            :user "svc-unvaulted"
            :evidence (make-map :vault-managed :false)
            :message "privileged account 'svc-unvaulted' is not vault-managed")
   (finding :missing-mfa :medium
            :user "analyst-nomfa"
            :evidence (make-map :mfa-enrolled :false :assurance :none)
            :message "active account 'analyst-nomfa' has no MFA enrolled")
   (finding :stale-token :medium
            :subject "svc-dormant"
            :evidence (make-map :token-id "tok-stale" :age-days 200 :ttl-days 180)
            :message "token 'tok-stale' (owner 'svc-dormant') exceeds max age of 180 days")))

(defun replace-user (estate id function)
  (map-set estate :users
           (map 'vector (lambda (user)
                          (if (equal id (map-get user :id))
                              (funcall function user)
                              user))
                (map-get estate :users)))
  estate)

(defun replace-token (estate id function)
  (map-set estate :tokens
           (map 'vector (lambda (token)
                          (if (equal id (map-get token :id))
                              (funcall function token)
                              token))
                (map-get estate :tokens)))
  estate)

(defun rules-of (findings)
  (map 'vector (lambda (item) (map-get item :rule)) findings))

(defun contract-triples (findings)
  (map 'vector (lambda (item)
                 (vector (map-get item :rule)
                         (map-get item :severity)
                         (or (map-get item :user) (map-get item :subject))))
       findings))

(defun multi-rule-set (kinds)
  "Compare two vectors of gap keywords irrespective of order."
  (sort (copy-list kinds) #'string< :key (lambda (keyword) (string-downcase (symbol-name keyword)))))

(deftest test-exact-five-finding-fixture-contract
  (let* ((findings (pam-audit.rules:audit-users
                    (pam-audit.fixture:estate-fixture)
                    (pam-audit.fixture:now-fixture)))
         (expected (expected-fixture-findings)))
    (is (= (length expected) (length findings)))
    (loop for index below (min (length expected) (length findings))
          do (is (pam-audit.util:map-equal (aref expected index) (aref findings index))
                 (format nil "finding ~a matches exactly" index)))
    (is (pam-audit.util:map-equal
         (make-map :total 5
                   :by-rule (make-map :inactive-privileged 1 :missing-mfa 1
                                      :orphaned-privileged 1 :stale-token 1
                                      :unvaulted-privileged 1)
                   :by-severity (make-map :high 2 :medium 3))
         (pam-audit.rules:summarize findings))
        "exact summary")))

(deftest test-all-six-rules-and-vector-order
  (let ((estate (pam-audit.fixture:estate-fixture)))
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
    (is-equal (vector (vector :orphaned-privileged :high "svc-orphan")
                      (vector :inactive-privileged :medium "svc-dormant")
                      (vector :never-logged-in-privileged :high "svc-ghost")
                      (vector :unvaulted-privileged :high "svc-unvaulted")
                      (vector :missing-mfa :medium "analyst-nomfa")
                      (vector :stale-token :medium "svc-dormant"))
              (contract-triples (pam-audit.rules:audit-users
                                 estate (pam-audit.fixture:now-fixture))))))

(deftest test-strict-day-and-token-thresholds
  (let* ((now (pam-audit.fixture:now-fixture))
         (dormant nil)
         (at-threshold nil)
         (over-threshold nil)
         (almost-threshold nil)
         (token-at-threshold (make-map :id "edge" :owner-id "svc-dormant"
                                       :created (- now (* 180 +day+)) :revoked :false))
         (token-over-threshold nil))
    (loop for user across (map-get (pam-audit.fixture:estate-fixture) :users)
          when (equal "svc-dormant" (map-get user :id))
            do (setf dormant user))
    (setf at-threshold (copy-map dormant))
    (map-set at-threshold :is-privileged t)
    (map-set at-threshold :last-login (- now (* 90 +day+)))
    (setf over-threshold (copy-map dormant))
    (map-set over-threshold :is-privileged t)
    (map-set over-threshold :last-login (- now (* 91 +day+)))
    (setf almost-threshold (copy-map dormant))
    (map-set almost-threshold :last-login (- now (+ (* 90 +day+) 86399)))
    (setf token-over-threshold (copy-map token-at-threshold))
    (map-set token-over-threshold :created (- now (* 181 +day+)))
    (is (= 90 (pam-audit.rules:days-between (map-get at-threshold :last-login) now)))
    (is (= 90 (pam-audit.rules:days-between (map-get almost-threshold :last-login) now)))
    (is-null (pam-audit.rules:inactive-privileged at-threshold now 90))
    (is (= 91 (map-get (map-get (pam-audit.rules:inactive-privileged over-threshold now 90)
                                :evidence)
                       :dormant-days)))
    (is-null (pam-audit.rules:stale-token token-at-threshold now 180))
    (is (= 181 (map-get (map-get (pam-audit.rules:stale-token token-over-threshold now 180)
                                 :evidence)
                        :age-days)))))

(deftest test-owner-kind-and-state-normalization
  (let ((user (make-map :id "subject" :is-privileged t :owner-id "owner"))
        (cases (list (list "active string human" (make-map :kind "human" :active t) nil)
                     (list "active keyword human" (make-map :kind :human :active t) nil)
                     (list "active string service" (make-map :kind "service" :active t) :not-human)
                     (list "active keyword service" (make-map :kind :service :active t) :not-human)
                     (list "inactive human" (make-map :kind "human" :active :false) :inactive))))
    (dolist (case cases)
      (destructuring-bind (label owner expected-state) case
        (let ((actual (pam-audit.rules:orphaned-privileged
                       user (let ((table (make-hash-table :test #'equal)))
                              (setf (gethash "owner" table) owner)
                              table)
                       (pam-audit.fixture:now-fixture))))
          (if expected-state
              (is (eq expected-state
                      (map-get (map-get actual :evidence) :owner-state))
                  label)
              (is-null actual label)))))
    (is (eq :missing
            (map-get (map-get (pam-audit.rules:orphaned-privileged
                               user (make-hash-table :test #'equal)
                               (pam-audit.fixture:now-fixture))
                              :evidence)
                     :owner-state)))))

(deftest test-portable-assurance-ranking-and-gap-order
  (is-equal (vector :none :password :mfa :adaptive-mfa :phishing-resistant)
            (pam-audit.policy:assurance-rank)
            "public ordered levels")
  (let ((expected-ranks (list (cons :none 0) (cons :password 1) (cons :mfa 2)
                              (cons :adaptive-mfa 3) (cons :phishing-resistant 4))))
    (dolist (actual (coerce (pam-audit.policy:assurance-rank) 'list))
      (dolist (minimum (coerce (pam-audit.policy:assurance-rank) 'list))
        (is (eq (pam-audit.util:boolean-value
                 (>= (cdr (assoc actual expected-ranks))
                     (cdr (assoc minimum expected-ranks))))
                (pam-audit.util:boolean-value
                 (pam-audit.policy:meets-assurance-p (make-map :assurance actual) minimum)))))))
  (is-true (pam-audit.policy:meets-assurance-p (make-map :assurance :unknown) :none))
  (is-false (pam-audit.util:boolean-value
             (pam-audit.policy:meets-assurance-p (make-map :assurance :unknown) :password)))
  (is-true (pam-audit.policy:meets-assurance-p (make-map) :none))
  (is-false (pam-audit.util:boolean-value (pam-audit.policy:meets-assurance-p (make-map) :password)))
  (is-true (pam-audit.policy:meets-assurance-p (make-map :assurance "mfa") "mfa"))
  (let* ((by-id (let ((table (make-hash-table :test #'equal)))
                  (loop for user across (map-get (pam-audit.fixture:estate-fixture) :users)
                        do (setf (gethash (map-get user :id) table) user))
                  table))
         (policies (map-get (pam-audit.fixture:estate-fixture) :policies))
         (privileged-without-mfa (copy-map (gethash "analyst-nomfa" by-id)))
         (below-assurance (copy-map (gethash "admin-active" by-id)))
         (without-mfa nil)
         (below nil))
    (map-set privileged-without-mfa :is-privileged t)
    (map-set below-assurance :is-privileged t)
    (map-set below-assurance :assurance :password)
    (map-set below-assurance :device-compliant :false)
    (setf without-mfa (pam-audit.policy:evaluate-user privileged-without-mfa policies))
    (setf below (pam-audit.policy:evaluate-user below-assurance policies))
    (is-equal (vector :mfa-not-enrolled :adaptive-mfa-missing :device-posture-unknown)
              (map 'vector (lambda (entry) (map-get entry :gap))
                   (map-get without-mfa :gaps)))
    (is-equal (vector :assurance-below-minimum :adaptive-mfa-missing :device-posture-unknown)
              (map 'vector (lambda (entry) (map-get entry :gap))
                   (map-get below :gaps)))))

(deftest test-wire-shape-and-normalizer-contract
  (let* ((normalized-user (make-map :id "u-1" :kind :service :active :false
                                    :owner-id "owner" :mfa-enrolled :false
                                    :assurance :none :vault-managed :false
                                    :device-compliant t :last-login 42))
         (wire-user (make-map :id "u-1" :userName "u-1" :kind "service" :active :false
                              :ownerId "owner" :mfaEnrolled :false :assurance "none"
                              :vaultManaged :false :deviceCompliant t :lastLogin 42))
         (normalized-token (make-map :id "t-1" :owner-id "owner"
                                     :created 42 :revoked t))
         (wire-token (make-map :id "t-1" :ownerId "owner"
                               :created 42 :revoked t))
         (normalized-policy (map-get (pam-audit.fixture:estate-fixture) :policies)))
    (is (pam-audit.util:map-equal wire-user (pam-audit.wire:user->wire normalized-user)))
    (is (pam-audit.util:map-equal normalized-user
                                   (pam-audit.normalize:normalize-user wire-user)))
    (is (pam-audit.util:map-equal
         (make-map :id "g-1" :privileged t :members (vector "u-1" "u-2"))
         (pam-audit.normalize:normalize-group
          (make-map :id "g-1" :privileged t :members (vector "u-1" "u-2")))))
    (is (pam-audit.util:map-equal wire-token (pam-audit.wire:token->wire normalized-token)))
    (is (pam-audit.util:map-equal normalized-token
                                   (pam-audit.normalize:normalize-token wire-token)))
    (is (pam-audit.util:map-equal
         (make-map :requireMfa t :minAssurance "mfa"
                   :requireAdaptiveMfa t :requireDevicePosture t
                   :maxInactiveDays 90 :privilegedTokenTtlDays 180
                   :requireVaulting t)
         (pam-audit.wire:policy->wire normalized-policy)))
    (is (pam-audit.util:map-equal
         normalized-policy
         (pam-audit.normalize:normalize-policy
          (pam-audit.wire:policy->wire normalized-policy))))
    (is (pam-audit.util:map-equal
         (make-map :id "default" :kind :human :active t :owner-id nil
                   :mfa-enrolled :false :assurance :none :vault-managed :false
                   :device-compliant :false :last-login nil)
         (pam-audit.normalize:normalize-user (make-map :userName "default"))))
    (is-false (map-get (pam-audit.normalize:normalize-user
                        (make-map :userName "inactive" :active :false))
                       :active))
    (is (pam-audit.util:map-equal
         (make-map :require-mfa :false :min-assurance :none
                   :require-adaptive-mfa :false :require-device-posture :false
                   :max-inactive-days 90 :privileged-token-ttl-days 180
                   :require-vaulting :false)
         (pam-audit.normalize:normalize-policy (make-map))))))

(deftest test-idsvc-inventory-translation-and-sponsor-binding
  (let* ((inventory (make-map :humans (vector (make-map :name "alice")
                                              (make-map :name "bob"))
                              :non_human_identities
                              (vector (make-map :name "worker" :sponsor "alice")
                                      (make-map :name "orphan"))))
         (estate (pam-audit.idsvc:inventory->estate inventory))
         (expected
           (make-map
            :users (vector
                    (make-map :id "alice" :kind :human :active t :owner-id nil
                              :mfa-enrolled :false :assurance :none
                              :vault-managed t :device-compliant :false :last-login nil)
                    (make-map :id "bob" :kind :human :active t :owner-id nil
                              :mfa-enrolled :false :assurance :none
                              :vault-managed t :device-compliant :false :last-login nil)
                    (make-map :id "worker" :kind :service :active t
                              :owner-id "alice" :mfa-enrolled t :assurance :mfa
                              :vault-managed t :device-compliant t :last-login nil)
                    (make-map :id "orphan" :kind :service :active t :owner-id nil
                              :mfa-enrolled t :assurance :mfa
                              :vault-managed t :device-compliant t :last-login nil))
            :groups (vector (make-map :id "vault-admins" :privileged t
                                      :members (vector "worker" "orphan")))
            :tokens (vector)
            :policies (make-map :require-mfa :false :max-inactive-days 90
                                :privileged-token-ttl-days 180)))
         (findings (pam-audit.rules:audit-users estate (pam-audit.fixture:now-fixture))))
    (is (pam-audit.util:map-equal expected estate) "translated estate")
    (is-equal (vector (vector :orphaned-privileged "orphan")
                      (vector :never-logged-in-privileged "worker")
                      (vector :never-logged-in-privileged "orphan"))
              (map 'vector (lambda (item)
                             (vector (map-get item :rule)
                                     (or (map-get item :user) (map-get item :subject))))
                   findings))))

(deftest test-group-membership-assignment-is-exact
  (let* ((users (vector (make-map :id "member" :kind :human :active t :owner-id "member"
                                  :mfa-enrolled t :assurance :adaptive-mfa
                                  :vault-managed :false :device-compliant t
                                  :last-login (pam-audit.fixture:now-fixture))
                        (make-map :id "outsider" :kind :human :active t :owner-id "outsider"
                                  :mfa-enrolled t :assurance :adaptive-mfa
                                  :vault-managed t :device-compliant t
                                  :last-login (pam-audit.fixture:now-fixture))))
         (groups (vector (make-map :id "privileged" :privileged t :members (vector "member"))
                         (make-map :id "ordinary" :privileged :false
                                   :members (vector "member" "outsider"))))
         (findings (pam-audit.rules:audit-users
                    (make-map :users users :groups groups :tokens (vector) :policies (make-map))
                    (pam-audit.fixture:now-fixture))))
    (is-equal (vector (vector :unvaulted-privileged "member"))
              (map 'vector (lambda (item) (vector (map-get item :rule) (map-get item :user)))
                   findings))))

(deftest test-single-field-repairs-remove-only-their-finding
  (let ((base-rules (vector :orphaned-privileged :inactive-privileged
                            :unvaulted-privileged :missing-mfa :stale-token))
        (owner-repaired nil)
        (mfa-repaired nil)
        (token-repaired nil))
    (setf owner-repaired (replace-user (pam-audit.fixture:estate-fixture) "svc-orphan"
                                       (lambda (user) (map-set user :owner-id "ciso"))))
    (setf mfa-repaired (replace-user (pam-audit.fixture:estate-fixture) "analyst-nomfa"
                                     (lambda (user) (map-set user :mfa-enrolled t))))
    (setf token-repaired (replace-token (pam-audit.fixture:estate-fixture) "tok-stale"
                                        (lambda (token)
                                          (map-set token :created
                                                   (- (pam-audit.fixture:now-fixture)
                                                      (* 180 +day+))))))
    (is-equal (vector :inactive-privileged :unvaulted-privileged :missing-mfa :stale-token)
              (rules-of (pam-audit.rules:audit-users owner-repaired
                                                    (pam-audit.fixture:now-fixture))))
    (is-equal (vector :orphaned-privileged :inactive-privileged
                      :unvaulted-privileged :stale-token)
              (rules-of (pam-audit.rules:audit-users mfa-repaired
                                                    (pam-audit.fixture:now-fixture))))
    (is-equal (vector :orphaned-privileged :inactive-privileged
                      :unvaulted-privileged :missing-mfa)
              (rules-of (pam-audit.rules:audit-users token-repaired
                                                    (pam-audit.fixture:now-fixture))))
    (is (= (length base-rules) 5))))

(deftest test-ageless-and-revoked-token-contract
  (let* ((ageless (make-map :id "tok-nodate" :owner-id "svc-dormant" :revoked :false))
         (finding (pam-audit.rules:stale-token ageless (pam-audit.fixture:now-fixture) 180)))
    (is (pam-audit.util:map-equal
         (finding :stale-token :medium
                  :subject "svc-dormant"
                  :evidence (make-map :token-id "tok-nodate" :age-days nil :ttl-days 180)
                  :message "token 'tok-nodate' (owner 'svc-dormant') has no creation timestamp; age unverifiable")
         finding))
    (is-null (pam-audit.rules:stale-token
              (let ((copy (copy-map ageless))) (map-set copy :revoked t) copy)
              (pam-audit.fixture:now-fixture) 180))))
