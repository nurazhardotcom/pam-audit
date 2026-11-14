;;;; package.lisp --- Test package for pam-audit.

(defpackage #:pam-audit.tests
  (:use #:cl)
  (:import-from #:pam-audit.util
                #:make-map
                #:map-get
                #:map-set
                #:copy-map)
  (:export #:run
           #:select
           #:deftest
           #:is
           #:signals
           #:*tests*
           #:*results*))
