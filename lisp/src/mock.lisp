;;;; mock.lisp --- In-process stub of a SCIM-shaped PAM REST API.
;;;;
;;;; Built only on SB-BSD-SOCKETS (shipped with SBCL) and pam-audit.json.
;;;; Serves the deterministic fixture estate with exactly 5 expected findings
;;;; (see fixture.lisp), so tests and demos can assert exact counts.

(in-package #:pam-audit.mock)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))

(defun wire-groups ()
  (map 'vector (lambda (group)
                 (make-map :id (map-get group :id)
                           :privileged (map-get group :privileged)
                           :members (map-get group :members)))
       (map-get (pam-audit.fixture:estate-fixture) :groups)))

(defun routes ()
  "Path -> response map.  Rebuilt per request so every response is fresh."
  (let ((estate (pam-audit.fixture:estate-fixture)))
    (let ((table (make-hash-table :test 'equal)))
      (setf (gethash "/oauth2/token" table)
            (make-map :status 200 :body (make-map :access_token "mock-token-123"
                                                 :token_type "Bearer"
                                                 :expires_in 3600)))
      (setf (gethash "/scim/v2/Users" table)
            (let ((users (map-get estate :users))
                  (resources (map 'vector #'pam-audit.wire:user->wire (map-get estate :users))))
              (make-map :status 200
                        :body (make-map :Resources resources :totalResults (length users)))))
      (setf (gethash "/scim/v2/Groups" table)
            (let ((groups (wire-groups)))
              (make-map :status 200
                        :body (make-map :Resources groups :totalResults (length groups)))))
      (setf (gethash "/api/v1/tokens" table)
            (let ((tokens (map-get estate :tokens))
                  (resources (map 'vector #'pam-audit.wire:token->wire (map-get estate :tokens))))
              (make-map :status 200
                        :body (make-map :Resources resources :totalResults (length tokens)))))
      (setf (gethash "/api/v1/policies/mfa" table)
            (make-map :status 200
                      :body (make-map :policy (pam-audit.wire:policy->wire
                                               (map-get estate :policies)))))
      table)))

(defun request-path (request-line)
  "Second whitespace-delimited token of REQUEST-LINE (the origin-form path)."
  (let ((parts (uiop:split-string request-line :separator '(#\Space))))
    (second parts)))

(defun read-request (stream)
  "Read request line + headers + body; returns a plist (:METHOD :PATH)."
  (let ((request-line (read-line stream nil nil))
        (content-length 0))
    (loop for line = (read-line stream nil nil)
          while (and line (not (string= (string-trim '(#\Return) line) "")))
          do (let* ((clean (string-right-trim '(#\Return) line))
                    (colon (position #\: clean))
                    (name (string-downcase (trim (subseq clean 0 colon))))
                    (value (trim (subseq clean (1+ colon)))))
               (when (string= name "content-length")
                 (setf content-length (or (parse-integer-or-nil value) 0)))))
    (when (plusp content-length)
      (read-line stream nil nil))
    (list :method (first (uiop:split-string (or request-line "") :separator '(#\Space)))
          :path (request-path (or request-line "")))))

(defun write-response (stream status body)
  (let* ((json (format nil "~a~%" (pam-audit.json:stringify body)))
         (octets (sb-ext:string-to-octets json :external-format :utf-8))
         (head (format nil "HTTP/1.1 ~a ~a~c~cContent-Type: application/json~c~cContent-Length: ~a~c~cConnection: close~c~c~c~c"
                       status (if (= status 200) "OK" "Not Found")
                       #\Return #\Newline #\Return #\Newline
                       (length octets)
                       #\Return #\Newline
                       #\Return #\Newline #\Return #\Newline)))
    (write-string head stream)
    (write-string json stream)
    (finish-output stream)))

(defun serve-one (socket)
  "Serve a single request on SOCKET, ignoring malformed client input."
  (let ((stream nil))
    (unwind-protect
         (handler-case
             (progn
               (setf stream (sb-bsd-sockets:socket-make-stream
                             socket :input t :output t
                             :element-type 'character
                             :external-format :utf-8))
               (let* ((request (read-request stream))
                      (route (gethash (getf request :path) (routes))))
                 (if route
                     (write-response stream (map-get route :status) (map-get route :body))
                     (write-response stream 404 (make-map :error "not found")))))
           (error () nil))
      (when stream (ignore-errors (close stream :abort t)))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun start-server (&key (port 0))
  "Start the stub API.  Returns a plist :PORT :BASE-URL :SOCKET.
Pass :PORT 0 (the default) for an ephemeral port."
  (let* ((socket (make-instance (find-class 'sb-bsd-sockets:inet-socket)
                                :type :stream :protocol :tcp))
         (address (make-array 4 :element-type '(unsigned-byte 8)
                                :initial-contents '(127 0 0 1))))
    (sb-bsd-sockets:socket-bind socket address port)
    (sb-bsd-sockets:socket-listen socket 16)
    (let ((actual (nth-value 1 (sb-bsd-sockets:socket-name socket))))
      (list :port actual
            :base-url (format nil "http://127.0.0.1:~a" actual)
            :socket socket))))

(defun server-port (server)
  (getf server :port))

(defun server-base-url (server)
  (getf server :base-url))

(defun stop-server (server)
  (let ((socket (getf server :socket)))
    (when socket
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun serve-forever (server &key (poll-seconds 0.02))
  "Accept and serve requests until the listening socket is closed by
STOP-SERVER or the process exits.  A closed socket surfaces as a socket
error, which ends the accept loop instead of spinning."
  (let ((socket (getf server :socket)))
    (loop
      (handler-case
          (serve-one (sb-bsd-sockets:socket-accept socket))
        (sb-bsd-sockets:socket-error () (return nil))
        (error () (sleep poll-seconds))))))
