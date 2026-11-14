;;;; util.lisp --- Strings, booleans, maps, sets, and small helpers.
;;;;
;;;; Value model shared with pam-audit.json:
;;;;   object  -> hash-table (test 'equal)
;;;;   array   -> vector
;;;;   true    -> T
;;;;   false   -> :FALSE
;;;;   null    -> NIL
;;;; Map keys are keywords for canonical data and strings for wire data.

(in-package #:pam-audit.util)

;;; ---------------------------------------------------------------------------
;;; Strings
;;; ---------------------------------------------------------------------------

(defun trim (string)
  (string-trim '(#\Space #\Tab #\Newline #\Return #\Page) string))

(defun blankp (value)
  "EDN-style blank?: NIL, the empty string, or whitespace-only text."
  (or (null value)
      (let ((string (if (stringp value) value (princ-to-string value))))
        (every (lambda (character)
                 (member character '(#\Space #\Tab #\Newline #\Return #\Page)
                         :test #'char=))
               string))))

(defun clj-str (value)
  "Approximate EDN's (str value) for the values this program handles."
  (cond
    ((null value) "")
    ((stringp value) value)
    ((eq value t) "true")
    ((eq value :false) "false")
    ((keywordp value)
     (format nil ":~a" (string-downcase (symbol-name value))))
    ((characterp value) (string value))
    (t (princ-to-string value))))

(defun keyword-name (keyword)
  (string-downcase (symbol-name keyword)))

(defun string-join (strings &optional (separator ""))
  (with-output-to-string (out)
    (let ((first t))
      (dolist (string strings)
        (if first
            (setf first nil)
            (write-string separator out))
        (write-string (clj-str string) out)))))

(defun starts-with-p (prefix string)
  (and (stringp prefix)
       (stringp string)
       (<= (length prefix) (length string))
       (string= prefix string :end2 (length prefix))))

(defun ends-with-p (suffix string)
  (and (stringp suffix)
       (stringp string)
       (<= (length suffix) (length string))
       (string= suffix string :start2 (- (length string) (length suffix)))))

(defun replace-all (old new string)
  (if (or (null old) (zerop (length old)))
      string
      (with-output-to-string (out)
        (loop with start = 0
              for position = (search old string :start2 start)
              while position
              do (write-string string out :start start :end position)
                 (write-string new out)
                 (setf start (+ position (length old)))
              finally (write-string string out :start start)))))

(defun split-string (string separator)
  "Split STRING on every occurrence of SEPARATOR (a string)."
  (let ((parts '())
        (start 0)
        (width (length separator)))
    (loop
      (let ((position (search separator string :start2 start)))
        (if position
            (progn
              (push (subseq string start position) parts)
              (setf start (+ position width)))
            (progn
              (push (subseq string start) parts)
              (return (nreverse parts))))))))

(defun parse-integer-or-nil (string)
  (when (stringp string)
    (multiple-value-bind (value position)
        (ignore-errors (parse-integer string :junk-allowed t))
      (when (and value (= position (length string)))
        value))))

;;; ---------------------------------------------------------------------------
;;; Booleans
;;; ---------------------------------------------------------------------------

(defparameter +json-null+ :null
  "Explicit JSON null marker for places NIL means 'absent' (e.g. hash values).")

(defun null-value (value)
  "Render VALUE as JSON null when it is NIL, otherwise VALUE."
  (if (null value) +json-null+ value))

(defun truthy (value)
  "EDN truthiness over this value model: NIL and :FALSE are false."
  (and value (not (eq value :false))))

(defun boolean-value (predicate)
  "Return T or :FALSE explicitly so JSON never has to guess."
  (if predicate t :false))

(defun equivp (value)
  "EDN's `true?`: literal T only.  :FALSE, NIL and anything else map to
:FALSE, so JSON prints the JSON boolean rather than a string."
  (if (eq value t) t :false))


;;; ---------------------------------------------------------------------------
;;; Maps (equal hash tables)
;;; ---------------------------------------------------------------------------

(defun make-map (&rest key-values)
  (let ((map (make-hash-table :test 'equal
                              :size (max 1 (floor (length key-values) 2)))))
    (loop for (key value) on key-values by #'cddr
          do (setf (gethash key map) value))
    map))

(defun map-get (map key &optional default)
  (if (hash-table-p map)
      (gethash key map default)
      default))

(defun map-has-p (map key)
  (and (hash-table-p map)
       (nth-value 1 (gethash key map))))

(defun map-get-any (map keys &optional default)
  "Return the value of the first key in KEYS that is present in MAP.
Present-but-NIL wins over a later key, matching EDN's get-with-default."
  (dolist (key keys default)
    (when (hash-table-p map)
      (multiple-value-bind (value present-p) (gethash key map)
        (when present-p (return value))))))

(defun map-has-any-p (map keys)
  (some (lambda (key) (map-has-p map key)) keys))

(defun map-set (map key value)
  (setf (gethash key map) value)
  map)

(defun copy-map (map)
  (let ((copy (make-hash-table :test (hash-table-test map)
                               :size (max 1 (hash-table-size map)))))
    (maphash (lambda (key value)
               (setf (gethash key copy) value))
             map)
    copy))

(defun map-keys (map)
  (let ((keys '()))
    (maphash (lambda (key value)
               (declare (ignore value))
               (push key keys))
             map)
    (nreverse keys)))

(defun map-values (map)
  (let ((values '()))
    (maphash (lambda (key value)
               (declare (ignore key))
               (push value values))
             map)
    (nreverse values)))

(defun map-remove (map key)
  (let ((copy (copy-map map)))
    (remhash key copy)
    copy))

(defun merge-maps (&rest maps)
  (let ((result (make-hash-table :test 'equal)))
    (dolist (map maps result)
      (when (hash-table-p map)
        (maphash (lambda (key value)
                   (setf (gethash key result) value))
                 map)))))

(defun keywordize (value)
  "Coerce a string, symbol, or keyword to an upcased keyword; NIL stays NIL."
  (cond
    ((null value) nil)
    ((keywordp value) value)
    ((stringp value) (intern (string-upcase value) :keyword))
    ((symbolp value) (intern (string-upcase (symbol-name value)) :keyword))
    (t (intern (string-upcase (princ-to-string value)) :keyword))))

(defun key-name (key)
  (cond
    ((keywordp key) (symbol-name key))
    ((stringp key) key)
    ((symbolp key) (symbol-name key))
    (t (princ-to-string key))))

(defun key-string= (left right)
  "Compare two map keys by their printable form, ignoring key type.
:MAX-INACTIVE-DAYS equals \"MAX-INACTIVE-DAYS\", not \"maxInactiveDays\"."
  (string= (key-name left) (key-name right)))

(defun sorted-keys (map)
  "Return MAP's keys sorted for deterministic output."
  (sort (copy-list (map-keys map))
        #'string<
        :key (lambda (key) (string-downcase (key-name key)))))

(defun keys-equal-p (left right)
  "Two map keys match when TEST would call them EQUAL or when their
printable forms are string= (so keywords and strings interoperate)."
  (or (equal left right) (string= (key-name left) (key-name right))))

(defun map-equal (left right &optional (test #'equal))
  "Structural equality for the value model: maps compare by key/value,
vectors elementwise, scalars with TEST (#'equal ignores key stringness)."
  (cond
    ((and (hash-table-p left) (hash-table-p right))
     (and (= (hash-table-count left) (hash-table-count right))
          (loop for key being the hash-keys of left using (hash-value value)
                always (multiple-value-bind (other present-p)
                           (gethash key right)
                         (and present-p
                              (map-equal value other test))))))
    ((or (hash-table-p left) (hash-table-p right)) (and (null left) (null right)))
    ((and (vectorp left) (vectorp right))
     (and (= (length left) (length right))
          (loop for index below (length left)
                always (map-equal (aref left index) (aref right index) test))))
    ((or (vectorp left) (vectorp right)) nil)
    (t (funcall test left right))))

;;; ---------------------------------------------------------------------------
;;; Sets (equal hash tables with T values)
;;; ---------------------------------------------------------------------------

(defun make-set (&rest members)
  (let ((set (make-hash-table :test 'equal)))
    (dolist (member members set)
      (setf (gethash member set) t))))

(defun set-add (set member)
  (setf (gethash member set) t)
  set)

(defun set-member-p (set member)
  (and (hash-table-p set)
       (nth-value 1 (gethash member set))))

;;; ---------------------------------------------------------------------------
;;; Clock
;;; ---------------------------------------------------------------------------

(defun current-epoch ()
  "Whole seconds since the Unix epoch."
  (- (get-universal-time) 2208988800))
