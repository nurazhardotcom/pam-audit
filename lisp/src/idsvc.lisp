;;;; idsvc.lisp --- Bridge: audit the sibling idsvc service by reading its
;;;; /inventory endpoint and translating it into the estate shape the rule
;;;; engine consumes.  idsvc already enforces sponsor binding, so a clean
;;;; report here is itself evidence (cf. T2 in the lab notes).

(in-package #:pam-audit.idsvc)

(defun collection (value)
  (cond
    ((vectorp value) value)
    ((null value) (vector))
    (t (coerce value 'vector))))

(defun human->user (human)
  (make-map :id (map-get human :name) :kind :human :active t
            :owner-id nil
            :mfa-enrolled :false :assurance :none
            :vault-managed t :device-compliant :false
            :last-login nil))

(defun nhi->user (nhi)
  (make-map :id (map-get nhi :name) :kind :service :active t
            :owner-id (map-get nhi :sponsor)
            :mfa-enrolled t :assurance :mfa
            :vault-managed t :device-compliant t
            :last-login nil))

(defun inventory->estate (inventory)
  "Translate idsvc inventory into {:users :groups :tokens :policies}.
Humans are non-privileged members of nothing; every NHI joins the privileged
group `vault-admins` so the orphaned/unvaulted rules apply to exactly the
right population."
  (let* ((humans (collection (map-get inventory :humans)))
         (nhis (collection (or (map-get inventory :non_human_identities)
                               (map-get inventory :non-human-identities)
                               (map-get inventory :nonHumanIdentities))))
         (members (map 'vector (lambda (nhi) (map-get nhi :name)) nhis)))
    (make-map
     :users (concatenate 'vector
                         (map 'vector #'human->user humans)
                         (map 'vector #'nhi->user nhis))
     :groups (vector (make-map :id "vault-admins" :privileged t :members members))
     :tokens (vector)
     ;; Conservative lab policy: idsvc has no MFA/token telemetry, so only the
     ;; sponsor-binding (orphan) rule carries signal here.
     :policies (make-map :require-mfa :false
                         :max-inactive-days 90
                         :privileged-token-ttl-days 180))))

(defun fetch-inventory (base-url)
  "GET /inventory from a running idsvc.  No auth is required (local lab), so
the anonymous flag is passed explicitly rather than implied."
  (pam-audit.scim:get-json base-url "/inventory" nil :allows-anonymous t))
