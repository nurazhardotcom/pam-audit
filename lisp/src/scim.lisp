;;;; scim.lisp --- SCIM-ish fetch layer: /Users, /Groups, /Tokens, /Policies.
;;;;
;;;; Plain GET + Bearer auth over the dependency-free HTTP client.  Response
;;;; shapes are normalized to the maps pam-audit.rules expects; the
;;;; normalization functions are pure and unit-tested without HTTP.

(in-package #:pam-audit.scim)

(defun joined-url (base-url path)
  (if (and (plusp (length base-url))
           (char= (char base-url (1- (length base-url))) #\/))
      (format nil "~a~a" base-url (string-left-trim "/" path))
      (format nil "~a~a" base-url path)))

(defun get-json (base-url path token &key allows-anonymous)
  "GET BASE-URL+PATH with Bearer TOKEN; returns the parsed body with keyword
keys.  A missing TOKEN is refused unless ALLOWS-ANONYMOUS is set (fail
closed: an audit without credentials must not silently read nothing)."
  (unless (or allows-anonymous (and token (plusp (length token))))
    (app-error* (format nil "GET ~a refused: no bearer token configured" path)))
  (let ((response (pam-audit.http:http-get
                   (joined-url base-url path)
                   :headers (append
                             (when (and token (plusp (length token)))
                               (list (cons "Authorization" (format nil "Bearer ~a" token))))
                             (list (cons "Accept" "application/json"))))))
    (if (= 200 (pam-audit.http:response-status response))
        (handler-case
            (pam-audit.json:parse (pam-audit.http:response-body response) :keywordize t)
          (pam-audit.json:json-error (condition)
            (app-error* (format nil "GET ~a returned invalid JSON" path)
                        (list :error (princ-to-string condition)))))
        (app-error* (format nil "GET ~a failed" path)
                    (list :status (pam-audit.http:response-status response)
                          :body (pam-audit.http:response-body response))))))

(defun resources (body key)
  "BODY's :RESOURCES (or KEY) as a vector; a missing collection is a hard
error so a schema drift cannot silently produce an empty clean audit."
  (let ((value (or (map-get body key) (map-get body :Resources))))
    (cond
      ((vectorp value) value)
      ((null value) (app-error* (format nil "response lacks ~a" key)))
      (t (coerce value 'vector)))))

(defun fetch-estate (base-url token)
  "Pull the whole estate from a SCIM-compatible API.  Returns
{:users [...] :groups [...] :tokens [...] :policies {...}} in the normalized
shape the rule engine consumes."
  (let ((users (get-json base-url "/scim/v2/Users" token))
        (groups (get-json base-url "/scim/v2/Groups" token))
        (tokens (get-json base-url "/api/v1/tokens" token))
        (policy (get-json base-url "/api/v1/policies/mfa" token)))
    (make-map
     :users (map 'vector #'pam-audit.normalize:normalize-user (resources users :Resources))
     :groups (map 'vector #'pam-audit.normalize:normalize-group (resources groups :Resources))
     :tokens (map 'vector #'pam-audit.normalize:normalize-token (resources tokens :Resources))
     :policies (pam-audit.normalize:normalize-policy (or (map-get policy :policy) (make-map))))))
