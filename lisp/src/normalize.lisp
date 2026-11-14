;;;; normalize.lisp --- Portable normalization from camelCase wire maps (or
;;;; local kebab-case maps) into the canonical estate shape consumed by the
;;;; rule engine.
;;;;
;;;; The same key is accepted in three spellings, tried in order:
;;;;   exact keyword (:USER-NAME), exact string ("userName"), and a
;;;;   case-insensitive printable-name match (:USERNAME / "username").
;;;; A present-but-NIL value wins over a later spelling, matching EDN's
;;;; (get m k default) semantics used by the original implementation.

(in-package #:pam-audit.normalize)

(defun lookup-first (map keys &optional default)
  "First present value among KEYS; a present NIL stops the search, which is
EDN's (get m k default) behaviour for the spelling alternatives."
  (dolist (key keys default)
    (multiple-value-bind (value present-p) (gethash-or-nil map key)
      (when present-p
        (return value)))))

(defun gethash-or-nil (map key)
  "VALUES: the value for KEY in MAP (exact keyword/string or case-folded)
and a present flag."
  (if (not (hash-table-p map))
      (values nil nil)
      (multiple-value-bind (value present-p) (gethash key map)
        (if present-p
            (values value t)
            (let ((string-key (if (keywordp key)
                                  (string-downcase (symbol-name key))
                                  key)))
              (multiple-value-bind (string-value string-p) (gethash string-key map)
                (if string-p
                    (values string-value t)
                    (loop for candidate being the hash-keys of map
                          when (and (or (keywordp candidate) (stringp candidate))
                                    (string-equal (key-name candidate) (key-name key)))
                            return (values (gethash candidate map) t)
                          finally (return (values nil nil))))))))))

(defun normalize-user (user)
  (make-map
   :id (lookup-first user '(:userName :user-name :username :id))
   :kind (keywordize (or (lookup-first user '(:kind)) "human"))
   :active (if (nth-value 1 (gethash-or-nil user :active))
               (boolean-value (truthy (lookup-first user '(:active))))
               t)
   :owner-id (lookup-first user '(:ownerId :owner-id :ownerid))
   :mfa-enrolled (boolean-value (truthy (lookup-first user '(:mfaEnrolled :mfa-enrolled :mfaenrolled))))
   :assurance (keywordize (or (lookup-first user '(:assurance)) "none"))
   :vault-managed (boolean-value (truthy (lookup-first user '(:vaultManaged :vault-managed :vaultmanaged))))
   :device-compliant (boolean-value (truthy (lookup-first user '(:deviceCompliant :device-compliant :devicecompliant))))
   :last-login (lookup-first user '(:lastLogin :last-login :lastlogin))))

(defun normalize-group (group)
  (make-map :id (lookup-first group '(:id))
            :privileged (boolean-value (truthy (lookup-first group '(:privileged))))
            :members (let ((members (lookup-first group '(:members) (vector))))
                       (if (vectorp members) members (vector)))))

(defun normalize-token (token)
  (make-map :id (lookup-first token '(:id))
            :owner-id (lookup-first token '(:ownerId :owner-id :ownerid))
            :created (lookup-first token '(:created))
            :revoked (boolean-value (truthy (lookup-first token '(:revoked))))))

(defun normalize-policy
    (policy)
  "Accept both wire (camelCase) and local (kebab-case) shapes."
  (make-map
   :require-mfa (boolean-value (truthy (lookup-first policy '(:requireMfa :require-mfa :requiremfa))))
   :min-assurance (keywordize (or (lookup-first policy '(:minAssurance :min-assurance :minassurance)) "none"))
   :require-adaptive-mfa (boolean-value
                          (truthy (lookup-first policy '(:requireAdaptiveMfa :require-adaptive-mfa
                                                                                 :requireadaptivemfa))))
   :require-device-posture (boolean-value
                            (truthy (lookup-first policy '(:requireDevicePosture :require-device-posture
                                                                                     :requiredeviceposture))))
   :max-inactive-days (or (lookup-first policy '(:maxInactiveDays :max-inactive-days :maxinactivedays)) 90)
   :privileged-token-ttl-days (or (lookup-first policy '(:privilegedTokenTtlDays :privileged-token-ttl-days
                                                                                  :privilegedtokenttldays))
                                  180)
   :require-vaulting (boolean-value (truthy (lookup-first policy '(:requireVaulting :require-vaulting
                                                                                  :requirevaulting))))))
