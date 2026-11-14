;;;; core.lisp --- Top-level entry points shared by the binary and the REPL.

(in-package #:pam-audit.core)

(defun usage (&optional (stream *error-output*))
  (pam-audit.cli:usage stream))

(defun command-line ()
  "Arguments after the executable name.  UIOP names this differently across
versions (ARGV / COMMAND-LINE-ARGUMENTS), so both are probed."
  (let ((symbol (or (find-symbol "COMMAND-LINE-ARGUMENTS" :uiop)
                    (find-symbol "ARGV" :uiop))))
    (if (and symbol (fboundp symbol))
        (coerce (funcall symbol) 'list)
        nil)))

(defun main (&optional (argv (command-line)))
  "Run the CLI on ARGV and RETURN the exit code (0 clean, 1 findings,
2 usage/runtime error).  Use ENTRY to terminate the process."
  (pam-audit.cli:main (coerce argv 'list)))

(defun entry (&optional (argv (command-line)))
  "Run the CLI on ARGV and exit the process with its exit code.  This is the
:toplevel installed by build.lisp."
  (sb-ext:exit :code (main argv) :abort nil))

(defparameter *standalone-p* nil
  "Set to T inside a dumped image (build.lisp sets it before saving).")

(defun standalone-p ()
  "True when running from the standalone binary rather than a REPL/script."
  (not (null *standalone-p*)))
