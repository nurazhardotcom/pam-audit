;;;; edn.lisp --- Deterministic EDN and S-expression printers.
;;;;
;;;; EDN is printed the way EDN's `prn` prints the equivalent literal:
;;;;   {:rule :stale-token :evidence {:age-days 200} :message "..."}
;;;; Maps print keys in sorted order so runs are byte-identical.  Vectors
;;;; print with square brackets in EDN and as lists in the S-expression view.
;;;; Value model: object -> hash-table, array -> vector, T / :FALSE / NIL,
;;;; NIL also prints as the symbol nil inside EDN collections.

(in-package #:pam-audit.edn)

(defparameter +edn-indent+ 2
  "Width of one indentation step for wrapped collections.")

(defparameter +edn-map-wrap+ 76
  "Maps wider than this print across lines, as EDN's pp does.")

(defun balanced-string-p (string)
  (zerop (loop with depth = 0
               for character across string
               do (case character
                    (#\{ (incf depth))
                    (#\} (decf depth))
                    (#\[ (incf depth))
                    (#\] (decf depth))
                    (#\" (return 1)))
               finally (return (if (zerop depth) 0 1)))))

(defun write-edn-string (string stream)
  (write-char #\" stream)
  (loop for character across string
        do (case character
             (#\" (write-string "\\\"" stream))
             (#\\ (write-string "\\\\" stream))
             (#\Newline (write-string "\\n" stream))
             (#\Tab (write-string "\\t" stream))
             (#\Return (write-string "\\r" stream))
             ((#\Page #\Backspace) (format stream "\\u~4,'0x" (char-code character)))
             (t (write-char character stream))))
  (write-char #\" stream))

(defun edn-key-sort-key (key)
  (string-downcase (key-name key)))

(defun write-edn-scalar (value stream)
  (cond
    ((eq value t) (write-string "true" stream))
    ((eq value :false) (write-string "false" stream))
    ((eq value :null) (write-string "nil" stream))
    ((null value) (write-string "nil" stream))
    ((stringp value) (write-edn-string value stream))
    ((keywordp value) (format stream ":~a" (keyword-name value)))
    ((integerp value) (format stream "~d" value))
    ((floatp value) (format stream "~g" value))
    ((symbolp value) (write-string (string-downcase (symbol-name value)) stream))
    (t (write-edn-string (princ-to-string value) stream))))

(defun collection-p (value)
  (or (hash-table-p value)
      (and (not (stringp value))
           (or (vectorp value) (consp value)))))

(defun edn-items (value)
  (etypecase value
    (vector value)
    (list (coerce value 'vector))))

(defun write-edn-value (value stream &optional (indent 0))
  (cond
    ((hash-table-p value)
     (write-edn-map value stream indent))
    ((collection-p value)
     (write-edn-vector (edn-items value) stream indent))
    (t (write-edn-scalar value stream))))

(defun edn-entry-string (key value indent)
  (with-output-to-string (out)
    (write-edn-value key out indent)
    (write-char #\Space out)
    (write-edn-scalar value out)))

(defun write-edn-map (map stream indent)
  (let ((entries '()))
    (maphash (lambda (key value)
               (push (cons key value) entries))
             map)
    (setf entries (sort entries #'string< :key (lambda (entry) (edn-key-sort-key (car entry)))))
    (if (null entries)
        (write-string "{}" stream)
        (let* ((rendered (mapcar (lambda (entry)
                                   (edn-entry-string (car entry) (cdr entry) indent))
                                 entries))
               (width (+ 2 (reduce (lambda (total entry)
                                     (+ total 1 (length entry)))
                                   rendered
                                   :initial-value 0)))
               (wrapped (> width +edn-map-wrap+)))
          (write-char #\{ stream)
          (loop for text in rendered
                for index from 0
                do (when (plusp index)
                     (if wrapped
                         (progn (terpri stream)
                                (loop repeat (+ indent +edn-indent+) do (write-char #\Space stream)))
                         (write-char #\Space stream)))
                   (write-string text stream))
          (when wrapped
            (terpri stream)
            (loop repeat indent do (write-char #\Space stream)))
          (write-char #\} stream)))))

(defun write-edn-vector (items stream indent)
  (if (zerop (length items))
      (write-string "[]" stream)
      (progn
        (write-char #\[ stream)
        (loop for item across (the vector items)
              for index from 0
              do (when (plusp index) (write-char #\Space stream))
                 (write-edn-value item stream (+ indent +edn-indent+)))
        (write-char #\] stream))))

(defun write-sexp-value (value stream)
  (cond
    ((hash-table-p value)
     (write-string "(" stream)
     (let ((first t))
       (dolist (key (sorted-keys value))
         (unless first (write-char #\Space stream))
         (setf first nil)
         (write-edn-value key stream)
         (write-char #\Space stream)
         (write-sexp-value (gethash key value) stream)))
     (write-char #\) stream))
    ((collection-p value)
     (write-string "(" stream)
     (let ((items (edn-items value))
           (first t))
       (loop for item across (the vector items)
             do (unless first (write-char #\Space stream))
                (setf first nil)
                (write-sexp-value item stream)))
     (write-char #\) stream))
    (t (write-edn-scalar value stream))))

(defun write-edn (value stream)
  (write-edn-value value stream 0)
  (terpri stream)
  value)

(defun write-sexp (value stream)
  (write-sexp-value value stream)
  (terpri stream)
  value)

(defun edn-string (value)
  "Return VALUE rendered as deterministic EDN text (no trailing newline)."
  (string-right-trim '(#\Newline) (with-output-to-string (out) (write-edn value out))))

(defun sexp-string (value)
  "Return VALUE rendered as deterministic S-expression text (no trailing newline)."
  (string-right-trim '(#\Newline) (with-output-to-string (out) (write-sexp value out))))
