;;;; rules.lisp --- Pure rule engine.
;;;;
;;;; Every rule is a pure function over plain maps: users, groups, tokens,
;;;; policies.  No I/O and no clock reads inside rules: callers pass NOW
;;;; (epoch seconds) so results are deterministic and trivially testable.
;;;;
;;;; Value model: missing booleans read as NIL (false); the canonical fixture
;;;; stores :FALSE for explicit false so reports can print `false`.

(in-package #:pam-audit.rules)

;;; ---------------------------------------------------------------------------
;;; Time helpers (pure)
;;; ---------------------------------------------------------------------------

(defparameter +seconds-per-day+ 86400)

(defun days-between (past now)
  "Whole days from epoch-seconds PAST to NOW, truncated toward zero."
  (truncate (- now past) +seconds-per-day+))

;;; ---------------------------------------------------------------------------
;;; Group membership
;;; ---------------------------------------------------------------------------

(defun privileged-member-ids (groups)
  "Equal hash set of every member id of every privileged group, computed
once per audit instead of rebuilding a set per user per group.  Accepts a
vector or a list of group maps."
  (let ((ids (make-set)))
    (loop for group across (if (vectorp groups) groups (coerce groups 'vector))
          when (truthy (map-get group :privileged))
            do (let ((members (map-get group :members)))
                 (loop for member across (if (vectorp members)
                                             members
                                             (coerce (or members '()) 'vector))
                       do (set-add ids member))))
    ids))

;;; ---------------------------------------------------------------------------
;;; Finding helpers
;;; ---------------------------------------------------------------------------

(defun finding (rule severity &key user subject evidence message)
  (let ((map (make-map :rule rule :severity severity)))
    (when user (map-set map :user user))
    (when subject (map-set map :subject subject))
    (map-set map :evidence evidence)
    (map-set map :message message)
    map))

;;; ---------------------------------------------------------------------------
;;; Individual rules (each returns NIL or a finding map)
;;; ---------------------------------------------------------------------------

(defun orphaned-privileged (user users-by-id now)
  "Privileged account whose owner/sponsor is missing or not itself an active
human.  Mirrors the CSA sponsor-binding gap: a privileged NHI or admin with
nobody accountable for it.  USERS-BY-ID maps id string -> user map."
  (let* ((owner-id (map-get user :owner-id))
         (owner (map-get users-by-id owner-id))
         (owner-kind (and owner (keywordize (map-get owner :kind)))))
    (when (and (truthy (map-get user :is-privileged))
               (or (null owner)
                   (not (eq :human owner-kind))
                   (not (truthy (map-get owner :active)))))
      (finding :orphaned-privileged :high
               :user (map-get user :id)
               :evidence (make-map :owner-id (null-value owner-id)
                                   :owner-state (cond ((null owner) :missing)
                                                      ((not (eq :human owner-kind)) :not-human)
                                                      (t :inactive))
                                   :checked-at now)
               :message (format nil "privileged account '~a' has no active human owner"
                                (map-get user :id))))))

(defun inactive-privileged (user now max-inactive-days)
  "Privileged account dormant beyond the inactivity threshold."
  (let ((last-login (map-get user :last-login)))
    (when (and (truthy (map-get user :is-privileged))
               (truthy (map-get user :active))
               last-login
               (> (days-between last-login now) max-inactive-days))
      (finding :inactive-privileged :medium
               :user (map-get user :id)
               :evidence (make-map :last-login last-login
                                   :dormant-days (days-between last-login now)
                                   :threshold-days max-inactive-days)
               :message (format nil "privileged account '~a' dormant beyond ~a days"
                                (map-get user :id) max-inactive-days)))))

(defun never-logged-in-privileged (user)
  "Active privileged account with no recorded login: there is no baseline to
judge it by, so it is flagged high instead of passing silently through the
dormancy rule (which needs a timestamp)."
  (when (and (truthy (map-get user :is-privileged))
             (truthy (map-get user :active))
             (null (map-get user :last-login)))
    (finding :never-logged-in-privileged :high
             :user (map-get user :id)
             :evidence (make-map :last-login (null-value nil))
             :message (format nil "privileged account '~a' has never logged in"
                              (map-get user :id)))))

(defun unvaulted-privileged (user)
  "Privileged account not under vault management (password/session not
brokered by the PAM vault)."
  (when (and (truthy (map-get user :is-privileged))
             (not (truthy (map-get user :vault-managed))))
    (finding :unvaulted-privileged :high
             :user (map-get user :id)
             :evidence (make-map :vault-managed :false)
             :message (format nil "privileged account '~a' is not vault-managed"
                              (map-get user :id)))))

(defun missing-mfa (user policy)
  "Active account without MFA enrollment while policy requires it."
  (when (and (truthy (map-get user :active))
             (truthy (map-get policy :require-mfa))
             (not (truthy (map-get user :mfa-enrolled))))
    (finding :missing-mfa
             (if (truthy (map-get user :is-privileged)) :high :medium)
             :user (map-get user :id)
             :evidence (make-map :mfa-enrolled :false
                                 :assurance (map-get user :assurance))
             :message (format nil "active account '~a' has no MFA enrolled"
                              (map-get user :id)))))

(defun stale-token (token now max-age-days)
  "API/token credential older than its allowed TTL.  A token with no creation
timestamp cannot prove its age and is flagged too (fail-closed): unknown age
reads as a finding, never as fresh."
  (cond
    ((truthy (map-get token :revoked)) nil)
    ((null (map-get token :created))
     (finding :stale-token :medium
              :subject (map-get token :owner-id)
              :evidence (make-map :token-id (map-get token :id)
                                  :age-days (null-value nil)
                                  :ttl-days max-age-days)
              :message (format nil "token '~a' (owner '~a') has no creation timestamp; age unverifiable"
                               (map-get token :id) (map-get token :owner-id))))
    ((> (days-between (map-get token :created) now) max-age-days)
     (finding :stale-token :medium
              :subject (map-get token :owner-id)
              :evidence (make-map :token-id (map-get token :id)
                                  :age-days (days-between (map-get token :created) now)
                                  :ttl-days max-age-days)
              :message (format nil "token '~a' (owner '~a') exceeds max age of ~a days"
                               (map-get token :id) (map-get token :owner-id) max-age-days)))))

;;; ---------------------------------------------------------------------------
;;; Entry point
;;; ---------------------------------------------------------------------------

(defun users-by-id (users)
  (let ((table (make-hash-table :test 'equal)))
    (loop for user across users
          do (setf (gethash (map-get user :id) table) user))
    table))

(defun audit-users (estate now)
  "Run every rule over ESTATE.  Returns a vector of finding maps in rule
order: orphaned, inactive, never-logged-in, unvaulted, missing-MFA, stale
tokens.  ESTATE = {:users [...] :groups [...] :tokens [...] :policies {...}}
and NOW is epoch seconds (caller-supplied for determinism)."
  (let* ((users (let ((users (map-get estate :users)))
                  (if (vectorp users) users (coerce (or users '()) 'vector))))
         (groups (map-get estate :groups))
         (tokens (let ((tokens (map-get estate :tokens)))
                   (if (vectorp tokens) tokens (coerce (or tokens '()) 'vector))))
         (policies (or (map-get estate :policies) (make-map)))
         (by-id (users-by-id users))
         (max-inactive (or (map-get policies :max-inactive-days) 90))
         (token-ttl (or (map-get policies :privileged-token-ttl-days) 180))
         (priv-ids (privileged-member-ids groups))
         (flagged (loop for user across users
                        collect (let ((copy (copy-map user)))
                                  (map-set copy :is-privileged
                                           (truthy (set-member-p priv-ids (map-get user :id))))
                                  copy)))
         (findings '()))
    (flet ((collect (rule)
             (dolist (user flagged)
               (let ((item (funcall rule user)))
                 (when item (push item findings))))))
      (collect (lambda (user) (orphaned-privileged user by-id now)))
      (collect (lambda (user) (inactive-privileged user now max-inactive)))
      (collect #'never-logged-in-privileged)
      (collect #'unvaulted-privileged)
      (collect (lambda (user) (missing-mfa user policies))))
    (loop for token across tokens
          for result = (stale-token token now token-ttl)
          when result do (push result findings))
    (coerce (nreverse findings) 'vector)))

(defun count-by (findings field)
  "Ordered alist keyed by sorted printable name of FINDINGS' FIELD value."
  (let ((table (make-hash-table :test 'equal)))
    (loop for item across findings
          for key = (map-get item field)
          do (incf (gethash key table 0)))
    (sort (loop for key being the hash-keys of table using (hash-value count)
                collect (cons key count))
          #'string< :key (lambda (pair) (key-name (car pair))))))

(defun counts-map (pairs)
  "Convert an ordered alist of keyword -> count into an insertion-ordered
map.  Consumers sort keys at print time anyway, so the map is plain."
  (let ((map (make-hash-table :test 'equal)))
    (dolist (pair pairs map)
      (setf (gethash (car pair) map) (cdr pair)))))

(defun summarize (findings)
  "Severity counts + totals for a findings vector."
  (make-map :total (length findings)
            :by-rule (counts-map (count-by findings :rule))
            :by-severity (counts-map (count-by findings :severity))))
