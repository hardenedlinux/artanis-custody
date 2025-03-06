;;  -*-  indent-tabs-mode:nil; coding: utf-8 -*-
;;  Copyright (C) 2025
;;      "Mu Lei" known as "NalaGinrut" <mulei@gnu.org>
;;  This is free software: you can redistribute it and/or modify
;;  it under the terms of the GNU General Public License and GNU
;;  Lesser General Public License published by the Free Software
;;  Foundation, either version 3 of the License, or (at your option)
;;  any later version.

;;  This is distributed in the hope that it will be useful,
;;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;  GNU General Public License and GNU Lesser General Public License
;;  for more details.

;;  You should have received a copy of the GNU General Public License
;;  and GNU Lesser General Public License along with this program.
;;  If not, see <http://www.gnu.org/licenses/>.

(define-module (custody vendor coinbase)
  #:use-module (artanis third-party json)
  #:use-module (ice-9 format)
  #:use-module (artanis client)
  #:export ())

(define *exchange-credentials*
  `((apiKey . "")
    (passphrase . "")
    (signingKey . "")))

(define *coinbase-sandbox-url*
  "https://api-public.sandbox.exchange.coinbase.com")

(define *coinbase-product-url*
  "https://api.exchange.coinbase.com")

(define *credential-file*
  (format #f "~a/prv/coinbase-credentials.json" (current-toplevel)))

(define current-credentials
  (make-parameter "BUG: No credentials loaded!"))

(define (load-credentials-file)
  (cond
   ((file-exists? *credential-file*)
    (current-credentials (call-with-input-file *credential-file* json->scm)))
   (else
    (display "No credentials file found!\n")
    (display "Please create prv/coinbase-credentials.json\n")
    (exit -1))))

(define* (build-jwt priv-key sec #:key (uri #f))
  (let ((data `((sub . ,key)
                (iss . "cdp")
                (nbf . ,(current-time))
                (exp . ,(+ (current-time) 3600))
                ,@(if uri `((uri . ,uri)) '())))
        (token (get-random-from-dev #:length 64)))
    (jwt-encode data
                priv-key
                #:algorithm 'RS256
                #:headers '((kid . ,priv-key)
                            (nonce . ,token)))))

(define (gen-jwt path)
  (let* ((creds (current-credentials))
         (priv-key (assoc-ref creds "signingKey"))
         (key (assoc-ref creds "apiKey")))
    (build-jwt priv-key key #:uri path)))

(define (coinbase/api-operate addr endpoint thunk)
  (let ((url (format #f "https://~a/~a" addr endpoint)))
    (call-with-values thunk
      (lambda (res body)
        (let ((code (response-code res))
              (scm (json-string->scm body)))
          (cond
           ((= code 200) scm)
           (else
            (throw 'artanis-err code coinbase/api-get
                   (assoc-ref scm "message")))))))))

(define (coinbase/api-get addr endpoint)
  (let ((jwt (gen-jwt endpoint)))
    (coinbase/api-operate
     addr endpoint
     (lambda ()
       (artanis:http-get url
                         #:headers `((content-type . "application/json")
                                     (authorization bearer ,jwt)))))))

(define (coinbase/api-delete addr endpoint)
  (let ((jwt (gen-jwt endpoint)))
    (coinbase/api-operate
     addr endpoint
     (lambda ()
       (artanis:http-delete url
                            #:headers `((content-type . "application/json")
                                        (authorization bearer ,jwt)))))))

(define (coinbase/api-patch addr endpoint data)
  (let ((jwt (gen-jwt endpoint)))
    (coinbase/api-operate
     addr endpoint
     (lambda ()
       (artanis:http-patch url
                           #:headers `((content-type . "application/json")
                                       (authorization bearer ,jwt))
                           #:body (scm->json-string data))))))

(define (coinbase/api-post addr endpoint data)
  (let ((jwt (gen-jwt endpoint)))
    (coinbase/api-operate
     addr endpoint
     (lambda ()
       (artanis:http-post url
                          #:headers `((content-type . "application/json")
                                      (authorization bearer ,jwt))
                          #:body data)))))

(define (coinbase/api-put addr endpoint data)
  (let ((jwt (gen-jwt endpoint)))
    (coinbase/api-operate
     addr endpoint
     (lambda ()
       (artanis:http-put url
                         #:headers `((content-type . "application/json")
                                     (authorization bearer ,jwt))
                         #:body data)))))

(define (scm->qstr scm)
  (cond
   ((string-join
     (call-with-output-string
      (lambda (port)
        (map
         (lambda (p)
           (format port "~a=~a" (car p) (cdr p)))
         scm)))
     "&")
    => (lambda (str)
         (if (string-null? str)
             ""
             (string-append "?" str))))
   (else (error "BUG: scm->qstr" scm))))

(define* (coinbase-get-accounts #:key (limit #f) (cursor #f)
                                (retail-portfolio-id #f))
  (let ((qstr (scm->qstr
               `(,@(if limit `((limit . ,limit)) '())
                 ,@(if cursor `((cursor . ,cursor)) '())
                 ,@(if retail-portfolio-id
                       `((retail_portfolio_id . ,retail-portfolio-id))
                       '())))))
    (coinbase/api-get *coinbase-product-url*
                      (format #f "/accounts?~a" qstr))))

(define (coinbase-get-account id)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/accounts/~a" id)))
