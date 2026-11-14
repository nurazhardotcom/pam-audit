;;;; wire.lisp --- Portable conversion from canonical normalized estate data
;;;; to the camelCase wire shape.  JSON serialization is a separate concern.

(in-package #:pam-audit.wire)

(defun name-of (value &optional (default ""))
  "EDN `(name x)` over our value model: keywords and strings both print."
  (cond
    ((null value) default)
    ((stringp value) value)
    ((keywordp value) (keyword-name value))
    (t (princ-to-string value))))

(defun user->wire (user)
  (make-map :id (map-get user :id)
            :userName (map-get user :id)
            :kind (name-of (map-get user :kind))
            :active (map-get user :active)
            :ownerId (map-get user :owner-id)
            :mfaEnrolled (map-get user :mfa-enrolled)
            :assurance (name-of (map-get user :assurance))
            :vaultManaged (map-get user :vault-managed)
            :deviceCompliant (map-get user :device-compliant)
            :lastLogin (map-get user :last-login)))

(defun token->wire (token)
  (make-map :id (map-get token :id)
            :ownerId (map-get token :owner-id)
            :created (map-get token :created)
            :revoked (map-get token :revoked)))

(defun policy->wire (policy)
  (make-map :requireMfa (map-get policy :require-mfa)
            :minAssurance (name-of (map-get policy :min-assurance))
            :requireAdaptiveMfa (map-get policy :require-adaptive-mfa)
            :requireDevicePosture (map-get policy :require-device-posture)
            :maxInactiveDays (map-get policy :max-inactive-days)
            :privilegedTokenTtlDays (map-get policy :privileged-token-ttl-days)
            :requireVaulting (map-get policy :require-vaulting)))
