;;;; auth.lisp --- Token acquisition: OAuth2 client-credentials grant or a
;;;; static ISPSS-style API token.  Uses pam-audit.http (SBCL sockets) and
;;;; pam-audit.json; no external dependencies.

(in-package #:pam-audit.auth)

(defun basic-auth (client-id client-secret)
  "Return the Authorization header value for HTTP basic auth."
  (format nil "Basic ~a"
          (pam-audit.http:base64-encode-string
           (format nil "~a:~a" (or client-id "") (or client-secret "")))))

(defun form-encode (pairs)
  "Encode (name . value) PAIRS as application/x-www-form-urlencoded."
  (with-output-to-string (out)
    (loop for (name . value) in pairs
          for index from 0
          do (when (plusp index) (write-char #\& out))
             (format out "~a=~a"
                     (pam-audit.http:url-encode (key-name name))
                     (pam-audit.http:url-encode (clj-str value))))))

(defun post-form (url form-params headers)
  "POST urlencoded FORM-PARAMS; returns the parsed JSON body (keyword keys).
Signals APP-ERROR on any non-200 status."
  (let ((response (pam-audit.http:http-post
                   url
                   :body (form-encode form-params)
                   :headers (append headers
                                    (list (cons "Content-Type"
                                                "application/x-www-form-urlencoded"))))))
    (if (= 200 (pam-audit.http:response-status response))
        (pam-audit.json:parse (pam-audit.http:response-body response) :keywordize t)
        (app-error* "token endpoint rejected request"
                    (list :status (pam-audit.http:response-status response)
                          :body (pam-audit.http:response-body response))))))

(defun client-credentials-token (cfg)
  "OAuth2 client-credentials flow.  Returns the access token string.
CFG keys: :token-url :client-id :client-secret :scope."
  (let* ((token-url (map-get cfg :token-url))
         (client-id (map-get cfg :client-id))
         (client-secret (map-get cfg :client-secret))
         (scope (map-get cfg :scope)))
    (unless (and token-url client-id client-secret)
      (app-error* "client-credentials needs --token-url, --client-id and --client-secret"
                  (list :token-url token-url
                        :client-id (and client-id t)
                        :client-secret (and client-secret t))))
    (let* ((params (append (list (cons "grant_type" "client_credentials"))
                           (when scope (list (cons "scope" scope)))))
           (body (post-form token-url params
                            (list (cons "Authorization" (basic-auth client-id client-secret)))))
           (token (map-get body :access_token)))
      (unless (and token (stringp token) (plusp (length token)))
        (app-error* "token endpoint returned no access_token"
                    (list :token-url token-url)))
      token)))

(defun resolve-token (cfg)
  "Return a bearer token from CFG: prefer :API-TOKEN (static ISPSS style),
else run the client-credentials flow."
  (or (map-get cfg :api-token)
      (client-credentials-token cfg)))
