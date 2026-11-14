;;;; policy-test.lisp --- MFA / assurance / device-posture policy tests.

(in-package #:pam-audit.tests)

(defun fixture-users-by-id ()
  (let ((table (make-hash-table :test #'equal)))
    (loop for user across (map-get (pam-audit.fixture:estate-fixture) :users)
          do (setf (gethash (map-get user :id) table) user))
    table))

(defun fixture-policies ()
  (map-get (pam-audit.fixture:estate-fixture) :policies))

(defun privileged-ids ()
  (pam-audit.util:make-set "admin-active" "svc-orphan" "svc-dormant" "svc-unvaulted"))

(defun gap-kinds (result)
  (map 'vector (lambda (entry) (map-get entry :gap)) (map-get result :gaps)))

(deftest test-privileged-without-adaptive-mfa-has-one-gap
  (let* ((user (copy-map (gethash "admin-active" (fixture-users-by-id))))
         (result nil))
    (map-set user :is-privileged t)
    (setf result (pam-audit.policy:evaluate-user user (fixture-policies)))
    (is-false (map-get result :compliant?))
    (is-equal (vector :adaptive-mfa-missing) (gap-kinds result))))

(deftest test-unenrolled-user-has-mfa-and-device-gaps
  (let* ((user (copy-map (gethash "analyst-nomfa" (fixture-users-by-id))))
         (result nil))
    (map-set user :is-privileged :false)
    (setf result (pam-audit.policy:evaluate-user user (fixture-policies)))
    (is-false (map-get result :compliant?))
    (is-equal ":device-posture-unknown and :mfa-not-enrolled"
              (let ((kinds (coerce (gap-kinds result) 'list)))
                (if (and (member :mfa-not-enrolled kinds)
                         (member :device-posture-unknown kinds)
                         (= 2 (length kinds)))
                    ":device-posture-unknown and :mfa-not-enrolled"
                    kinds)))))

(deftest test-fully-compliant-user
  (let* ((user (copy-map (gethash "ciso" (fixture-users-by-id))))
         (result nil))
    (map-set user :is-privileged :false)
    (setf result (pam-audit.policy:evaluate-user user (fixture-policies)))
    (is-true (map-get result :compliant?))
    (is (= 0 (length (map-get result :gaps))))))

(deftest test-evaluate-all-splits-population
  (let* ((split (pam-audit.policy:evaluate-all
                 (map-get (pam-audit.fixture:estate-fixture) :users)
                 (fixture-policies)
                 (privileged-ids)))
         (compliant (map-get split :compliant))
         (non-compliant (map-get split :non-compliant))
         (bad-ids '()))
    (is (= 1 (length compliant)))
    (is (equal "ciso" (map-get (aref compliant 0) :user)))
    (loop for entry across non-compliant
          do (push (map-get entry :user) bad-ids))
    (is-equal '("admin-active" "svc-orphan" "svc-dormant" "svc-unvaulted" "analyst-nomfa")
              (sort bad-ids #'string<))))
