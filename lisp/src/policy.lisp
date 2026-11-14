;;;; policy.lisp --- Policy evaluation: does each account meet the MFA /
;;;; device-posture policy?  Pure functions with the same determinism contract
;;;; as pam-audit.rules: no I/O and no clock reads.

(in-package #:pam-audit.policy)

(defparameter +assurance-rank+
  '(:none :password :mfa :adaptive-mfa :phishing-resistant)
  "Ordered assurance levels; higher index = stronger.")

(defun assurance-rank ()
  "Return the public ordered assurance-level vector."
  (coerce +assurance-rank+ 'vector))

(defun assurance-position (level)
  "Index of LEVEL in the rank order.  Strings and keywords compare by name;
unknown levels rank 0, matching the original keep-indexed behaviour."
  (let ((wanted (keywordize level)))
    (or (position wanted +assurance-rank+ :test #'eq) 0)))

(defun meets-assurance-p (user min-assurance)
  "True when USER's assurance level meets the policy minimum."
  (>= (assurance-position (map-get user :assurance))
      (assurance-position min-assurance)))

(defun gap (kind detail)
  (make-map :gap kind :detail detail))

(defun evaluate-user (user policy)
  "Evaluate one USER against the MFA/device POLICY.  Returns a map with
:COMPLIANT? plus a vector of :GAPS (each {:gap <kw> :detail <str>}).
Gap order is causal and deterministic: MFA, assurance, adaptive MFA, device."
  (let ((gaps '())
        (require-mfa (truthy (map-get policy :require-mfa)))
        (mfa-enrolled (truthy (map-get user :mfa-enrolled)))
        (privileged (truthy (map-get user :is-privileged)))
        (assurance (map-get user :assurance)))
    (when (and require-mfa (not mfa-enrolled))
      (push (gap :mfa-not-enrolled "MFA required by policy but not enrolled") gaps))
    (when (and mfa-enrolled
               (map-get policy :min-assurance)
               (not (meets-assurance-p user (map-get policy :min-assurance))))
      (push (gap :assurance-below-minimum
                 (format nil "assurance ~a below minimum ~a"
                         (keyword-name (keywordize assurance))
                         (keyword-name (keywordize (map-get policy :min-assurance)))))
            gaps))
    (when (and (truthy (map-get policy :require-adaptive-mfa))
               privileged
               (not (eq (keywordize assurance) :adaptive-mfa))
               (not (eq (keywordize assurance) :phishing-resistant)))
      (push (gap :adaptive-mfa-missing "privileged account lacks adaptive MFA assurance") gaps))
    (when (and (truthy (map-get policy :require-device-posture))
               (not (truthy (map-get user :device-compliant))))
      (push (gap :device-posture-unknown "no compliant device binding on record") gaps))
    (let ((ordered (coerce (nreverse gaps) 'vector)))
      (make-map :user (map-get user :id)
                :compliant? (equivp (zerop (length ordered)))
                :gaps ordered))))

(defun evaluate-all (users policy privileged-ids)
  "Evaluate every user; returns {:compliant [...] :non-compliant [...]},
each entry the per-user map from EVALUATE-USER.  PRIVILEGED-IDS is an equal
hash set of ids (see pam-audit.util:make-set)."
  (let ((compliant '())
        (non-compliant '()))
    (loop for user across users
          for copy = (let ((copy (copy-map user)))
                       (map-set copy :is-privileged
                                (equivp (set-member-p privileged-ids (map-get user :id))))
                       copy)
          for result = (evaluate-user copy policy)
          do (if (truthy (map-get result :compliant?))
                 (push result compliant)
                 (push result non-compliant)))
    (make-map :compliant (coerce (nreverse compliant) 'vector)
              :non-compliant (coerce (nreverse non-compliant) 'vector))))
