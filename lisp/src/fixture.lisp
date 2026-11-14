;;;; fixture.lisp --- Portable deterministic fixture data.
;;;;
;;;; This canonical normalized map is the source of truth for the demo and
;;;; the tests.  Wire-shape conversion lives in pam-audit.wire and the HTTP
;;;; mock serves these exact values.

(in-package #:pam-audit.fixture)

(defparameter +seconds-per-day+ 86400)

(defparameter +now-fixture+ 1788460800
  "Fixed clock for determinism: 2026-09-05T00:00:00Z.")

(defun now-fixture ()
  "The fixed fixture clock (function form for callers that take a clock)."
  +now-fixture+)

(defun days-ago (days)
  (- +now-fixture+ (* days +seconds-per-day+)))

(defun make-user (id kind active owner-id mfa-enrolled assurance vault-managed
                  device-compliant last-login)
  (make-map :id id :kind kind :active active :owner-id owner-id
            :mfa-enrolled mfa-enrolled :assurance assurance
            :vault-managed vault-managed :device-compliant device-compliant
            :last-login last-login))

(defun estate-fixture ()
  "Fresh copy of the canonical six-user estate.  Each call rebuilds the
tables so tests can mutate results without disturbing later calls."
  (make-map
   :users
   (vector
    (make-user "ciso" :human t nil t :adaptive-mfa t t (days-ago 1))
    (make-user "admin-active" :human t "ciso" t :mfa t t (days-ago 2))
    (make-user "svc-orphan" :service t nil t :mfa t t (days-ago 2))
    (make-user "svc-dormant" :service t "ciso" t :mfa t t (days-ago 120))
    (make-user "svc-unvaulted" :service t "ciso" t :mfa :false t (days-ago 3))
    (make-user "analyst-nomfa" :human t nil :false :none t :false (days-ago 1)))
   :groups
   (vector
    (make-map :id "vault-admins" :privileged t
              :members (vector "admin-active" "svc-orphan" "svc-dormant" "svc-unvaulted"))
    (make-map :id "analysts" :privileged :false
              :members (vector "analyst-nomfa" "ciso")))
   :tokens
   (vector
    (make-map :id "tok-stale" :owner-id "svc-dormant"
              :created (days-ago 200) :revoked :false)
    (make-map :id "tok-fresh" :owner-id "admin-active"
              :created (days-ago 2) :revoked :false))
   :policies
   (make-map :require-mfa t
             :min-assurance :mfa
             :require-adaptive-mfa t
             :require-device-posture t
             :max-inactive-days 90
             :privileged-token-ttl-days 180
             :require-vaulting t)))

(defun inventory-fixture ()
  "A small idsvc-shaped inventory used by the idsvc translation tests and
the `audit --idsvc` smoke path."
  (make-map
   :humans (vector (make-map :name "alice")
                   (make-map :name "bob"))
   :non_human_identities (vector (make-map :name "worker" :sponsor "alice")
                                 (make-map :name "orphan"))))
