;;;; harness.lisp --- Plain ANSI Common Lisp test harness.
;;;;
;;;; Zero FiveAM/Rove dependency: DEFTEST registers a thunk, IS records an
;;;; assertion with a printable report, SIGNALS checks that a form signals.
;;;; RUN executes every registered test, prints a EDN-test-style summary
;;;; and returns T when every assertion passed.

(in-package #:pam-audit.tests)

(defvar *tests* '()
  "Registered tests as (name . thunk) in definition order.")

(defstruct test-results
  (tests 0)
  (assertions 0)
  (failures 0)
  (failures-log '()))

(defvar *results* (make-test-results))

(defmacro deftest (name &body body)
  "Register NAME as a test with a thunk running BODY."
  `(progn
     (setf *tests* (remove ',name *tests* :key #'car))
     (setf *tests* (append *tests* (list (cons ',name (lambda () ,@body)))))
     ',name))

(defun results-record-failure (label report)
  (incf (test-results-failures *results*))
  (push (list label report) (test-results-failures-log *results*))
  (format t "~&FAIL ~a~@[~%     ~a~]~%" label report)
  (finish-output))

(defmacro is (form &optional description)
  "Assert FORM is true.  DESCRIPTION is an optional human label."
  `(progn
     (incf (test-results-assertions *results*))
     (let ((value ,form))
       (if value
           t
           (results-record-failure
            (or ,description (format nil "~s" ',form))
            (format nil "expected ~s to be true~@[ (case: ~a)~]" ',form ,description))))))

(defmacro is-equal (expected actual &optional description)
  "Assert (EQUAL EXPECTED ACTUAL), reporting both values on failure."
  `(progn
     (incf (test-results-assertions *results*))
     (let ((expected-value ,expected)
           (actual-value ,actual))
       (if (equal expected-value actual-value)
           t
           (results-record-failure
            (or ,description (format nil "~s = ~s" ',actual ',expected))
            (format nil "expected ~s~%     got      ~s" expected-value actual-value))))))

(defmacro is-null (form &optional description)
  (let ((value (gensym "VALUE")))
    `(let ((,value ,form))
       (incf (test-results-assertions *results*))
       (if (null ,value)
           t
           (results-record-failure
            (or ,description (format nil "~s is null" ',form))
            (format nil "expected NIL, got ~s" ,value))))))

(defmacro is-true (form &optional description)
  "Assert FORM's value is literally T (EDN's `true?`)."
  (let ((value (gensym "VALUE")))
    `(let ((,value ,form))
       (incf (test-results-assertions *results*))
       (if (eq ,value t)
           t
           (results-record-failure
            (or ,description (format nil "~s is true" ',form))
            (format nil "expected T, got ~s" ,value))))))

(defmacro is-false (form &optional description)
  "Assert FORM's value is literally :FALSE (the JSON false marker)."
  (let ((value (gensym "VALUE")))
    `(let ((,value ,form))
       (incf (test-results-assertions *results*))
       (if (eq ,value :false)
           t
           (results-record-failure
            (or ,description (format nil "~s is false" ',form))
            (format nil "expected :FALSE, got ~s" ,value))))))

(defmacro signals (condition-type &body body)
  "Assert that BODY signals CONDITION-TYPE."
  `(progn
     (incf (test-results-assertions *results*))
     (handler-case
         (progn ,@body
                (results-record-failure
                 (format nil "signals ~a" ',condition-type)
                 "the form returned normally instead of signalling")
                nil)
       (,condition-type () t)
       (error (condition)
         (results-record-failure
          (format nil "signals ~a" ',condition-type)
          (format nil "signalled the wrong condition: ~a" condition))
         nil))))

(defun run (&optional (tests (reverse *tests*)) (stream *standard-output*))
  "Run TESTS in order; print a summary to STREAM; return T when all passed."
  (let ((*results* (make-test-results))
        (*standard-output* stream))
    (loop for (name . thunk) in tests
          do (incf (test-results-tests *results*))
             (handler-case (funcall thunk)
               (error (condition)
                 (results-record-failure
                  (format nil "~a (error)" name)
                  (format nil "unexpected error: ~a" condition)))))
    (dolist (failure (reverse (test-results-failures-log *results*)))
      (format stream "  ~a: ~a~%" (first failure) (second failure)))
    (format stream "~&Ran ~a test~:p / ~a assertion~:p, ~a failure~:p, 0 errors~%"
            (test-results-tests *results*)
            (test-results-assertions *results*)
            (test-results-failures *results*))
    (finish-output stream)
    (zerop (test-results-failures *results*))))
