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
  #:use-module (custody utils)
  #:use-module (artanis third-party json)
  #:use-module (ice-9 format)
  #:use-module (artanis client)
  #:export (
            coinbase-get-accounts
            coinbase-get-account
            coinbase-get-account-holds
            coinbase-get-account-ledger

            coinbase-get-address-book

            coinbase-get-coinbase-accounts
            coinbase-post-coinbase-accounts-addr

            coinbase-post-conversions
            coinbase-get-conversions
            coinbase-get-conversions-fees
            coinbase-get-conversions-id

            coinbase-get-currencies
            coinbase-get-currencies-id

            coinbase-post-deposits-coinbase-account
            coinbase-post-deposits-payment-method
            coinbase-get-payment-methods
            coinbase-get-transfers
            coinbase-get-transfers-id

            coinbase-post-transfers-travel-rules

            coinbase-post-withdrawals-coinbase-account
            coinbase-post-withdrawals-crypto
            coinbase-get-withdrawals-fee-estimate
            coinbase-post-withdrawals-payment-method

            coinbase-get-fees

            coinbase-get-fills
            coinbase-get-orders
            coinbase-delete-orders
            coinbase-post-orders
            coinbase-get-orders-id
            coinbase-delete-orders-id

            coinbase-get-loans
            coinbase-get-loans-assets
            coinbase-get-loans-interest
            coinbase-get-loans-interest-history
            coinbase-get-loans-interest-id
            coinbase-get-loans-lending-overview
            coinbase-get-loans-loan-preview
            coinbase-post-loans-open

            coinbase-get-loans-options
            coinbase-post-loans-repay-interest
            coinbase-post-loans-repay-principal
            coinbase-get-loans-repayment-preview

            coinbase-get-margin-auto-loan
            coinbase-post-margin-auto-loan
            coinbase-get-margin-usdc
            coinbase-post-margin-usdc

            coinbase-get-oracle

            coinbase-get-products
            coinbase-get-products-volume-summary
            coinbase-get-products-id
            coinbase-get-products-id-book
            coinbase-get-products-id-candles
            coinbase-get-products-id-stats
            coinbase-get-products-id-ticker
            coinbase-get-products-id-trades

            coinbase-get-profiles
            coinbase-post-profiles
            coinbase-post-profiles-transfer
            coinbase-get-profiles-id
            coinbase-put-profiles-id
            coinbase-put-profiles-id-deactivate

            coinbase-get-reports
            coinbase-post-reports
            coinbase-get-reports-id

            coinbase-get-travel-rules
            coinbase-post-travel-rules
            coinbase-delete-travel-rules-id

            coinbase-get-users-id-exchange-limits
            coinbase-post-users-id-settlement-preferences
            coinbase-get-users-id-trading-volumes

            coinbase-get-wrapped-assets
            coinbase-get-wrapped-assets-stake-wrap
            coinbase-post-wrapped-assets-stake-wrap
            coinbase-get-wrapped-assets-stake-wrap-id))

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

(define (init-credentials-file)
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

;; API --------------------------------------------------------------


;; Accounts

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

(define (coinbase-get-account-holds id)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/accounts/~a/holds" id)))

(define (coinbase-get-account-ledger id)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/accounts/~a/ledger" id)))

(define (coinbase-get-account-transfers id)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/accounts/~a/transfers" id)))

;; Addresses book

(define (coinbase-get-address-book)
  (coinbase/api-get *coinbase-product-url* "/address-book"))

(define (coinbase-post-address-book currency label is_verified_self_hosted_wallet vasp_id address destination_tag)
  (coinbase/api-post *coinbase-product-url* "/address-book"
                     (scm->json-string `((addresses . ((0 . ((currency . ,currency)
                                                             (label . ,label)
                                                             (is_verified_self_hosted_wallet . ,is_verified_self_hosted_wallet)
                                                             (vasp_id . ,vasp_id)))
                                                       (to . ((address . ,address)
                                                              (destination_tag . ,destination_tag)))))))))

(define (coinbase-delete-address-book id)
  (coinbase/api-delete *coinbase-product-url*
                       (format #f "/address-book/~a" id)))

;; Coinbase Accounts

(define (coinbase-get-coinbase-accounts)
  (coinbase/api-get *coinbase-product-url* "/coinbase-accounts"))

(define (coinbase-post-coinbase-accounts-addr aid pid net)
  (coinbase/api-post *coinbase-product-url*
                     (format #f "/coinbase-accounts/~a/addresses" aid)
                     (scm->json-string `((account_id . ,aid)
                                         (profile_id . ,pid)
                                         (network . ,net)))))

;; Conversion

(define (coinbase-post-conversions pid from to amount)
  (coinbase/api-post *coinbase-product-url* "/conversions"
                     (scm->json-string `((profile_id . ,pid)
                                         (from . ,from)
                                         (to . ,to)
                                         (amount . ,amount)
                                         (nonce . ,(gen-random-nonce/str))))))

(define (coinbase-get-conversions pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/conversions?profile_id=~a" pid)))

(define (coinbase-get-conversions-fees)
  (coinbase/api-get *coinbase-product-url* "/conversions/fees"))

(define (coinbase-get-conversions-id cid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/conversions/~a" cid)))

;; Currencies

(define (coinbase-get-currencies)
  (coinbase/api-get *coinbase-product-url* "/currencies"))

(define (coinbase-get-currencies-id cid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/currencies/~a" cid)))

;; Transfers

(define (coinbase-post-deposits-coinbase-account pid amount aid curr)
  (coinbase/api-post *coinbase-product-url* "/deposits/coinbase-account"
                     (scm->json-string `((profile_id . ,pid)
                                         (amount . ,amount)
                                         (coinbase_account_id . ,aid)
                                         (currency . ,curr)))))

(define (coinbase-post-deposits-payment-method pid amount mid curr)
  (coinbase/api-post *coinbase-product-url* "/deposits/payment-method"
                     (scm->json-string `((profile_id . ,pid)
                                         (amount . ,amount)
                                         (payment_method_id . ,mid)
                                         (currency . ,curr)))))

(define (coinbase-get-payment-methods)
  (coinbase/api-get *coinbase-product-url* "/payment-methods"))

(define (coinbase-get-transfers)
  (coinbase/api-get *coinbase-product-url* "/transfers"))

(define (coinbase-get-transfers-id tid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/transfers/~a" tid)))

(define (coinbase-post-transfers-travel-rules tid orig-name orig-country)
  (coinbase/api-post *coinbase-product-url*
                     (format #f "/transfers/~a/travel-rules" tid)
                     (scm->json-string `((transfer_id . ,tid)
                                         (originator_name . ,orig-name)
                                         (originator_country . ,orig-country)))))

(define (coinbase-post-withdrawals-coinbase-account pid amount aid curr)
  (coinbase/api-post *coinbase-product-url* "/withdrawals/coinbase-account"
                     (scm->json-string `((profile_id . ,pid)
                                         (amount . ,amount)
                                         (coinbase_account_id . ,aid)
                                         (currency . ,curr)))))

(define (coinbase-post-withdrawals-crypto pid amount curr crypto-addr no_des_tag des-tag network)
  (coinbase/api-post *coinbase-product-url* "/withdrawals/crypto"
                     (scm->json-string `((profile_id . ,pid)
                                         (amount . ,amount)
                                         (currency . ,curr)
                                         (crypto_address . ,crypto-addr)
                                         (destination_tag . ,des-tag)
                                         (no_destination_tag . ,no_des_tag)
                                         (nonce . ,(gen-random-nonce/num))
                                         (network . ,network)))))

(define (coinbase-get-withdrawals-fee-estimate)
  (coinbase/api-get *coinbase-product-url* "/withdrawals/fee-estimate"))

(define (coinbase-post-withdrawals-payment-method pid amount mid curr)
  (coinbase/api-post *coinbase-product-url* "/withdrawals/payment-method"
                     (scm->json-string `((profile_id . ,pid)
                                         (amount . ,amount)
                                         (payment_method_id . ,mid)
                                         (currency . ,curr)))))

;; Fees

(define (coinbase-get-fees)
  (coinbase/api-get *coinbase-product-url* "/fees"))

;; Orders

(define (coinbase-get-fills)
  (coinbase/api-get *coinbase-product-url* "/fills"))

(define (coinbase-get-orders)
  (coinbase/api-get *coinbase-product-url* "/orders"))

(define (coinbase-delete-orders)
  (coinbase/api-delete *coinbase-product-url* "/orders"))

(define* (coinbase-post-orders profile_id side price stop_price
                               size funds client_oid max_floor
                               stop_limit_price
                               #:keys (type "limit")
                               (stp "dc") (stop "loss")
                               (time_in_force "GTC") (cancel_after "min")
                               (post_only #f))
  (coinbase/api-post *coinbase-product-url* "/orders"
                     (scm->json-string `((profile_id . ,profile_id)
                                         (type . ,type)
                                         (side . ,side)
                                         (stp . ,stp)
                                         (stop . ,stop)
                                         (stop_price . ,stop_price)
                                         (price . ,price)
                                         (size . ,size)
                                         (funds . ,funds)
                                         (time_in_force . ,time_in_force)
                                         (cancel_after . ,cancel_after)
                                         (post_only . ,post_only)
                                         (client_oid . ,client_oid)
                                         (max_floor . ,max_floor)
                                         (stop_limit_price . ,stop_limit_price)))))

(define (coinbase-get-orders-id oid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/orders/~a" oid)))

(define (coinbase-delete-orders-id oid)
  (coinbase/api-delete *coinbase-product-url*
                       (format #f "/orders/~a" oid)))

;; Loans

(define (coinbase-get-loans)
  (coinbase/api-get *coinbase-product-url* "/loans"))

(define (coinbase-get-loans-assets)
  (coinbase/api-get *coinbase-product-url* "/loans/assets"))

(define (coinbase-get-loans-interest)
  (coinbase/api-get *coinbase-product-url* "/loans/interest"))

(define (coinbase-get-loans-interest-history lid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/loans/interest/history/~a" lid)))

(define (coinbase-get-loans-interest-id lid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/loans/interest/~a" lid)))

(define (coinbase-get-loans-lending-overview)
  (coinbase/api-get *coinbase-product-url* "/loans/lending-overview"))

(define (coinbase-get-loans-loan-preview)
  (coinbase/api-get *coinbase-product-url* "/loans/loan-preview"))

(define (coinbase-post-loans-open lid curr native-amount interest-rate
                                  term-start-date term-end-date profile-id)
  (coinbase/api-post *coinbase-product-url* "/loans/open"
                     (scm->json-string `((loan_id . ,lid)
                                         (currency . ,curr)
                                         (native_amount . ,native-amount)
                                         (interest_rate . ,interest-rate)
                                         (term_start_date . ,term-start-date)
                                         (term_end_date . ,term-end-date)
                                         (profile_id . ,profile-id)))))

(define (coinbase-get-loans-options)
  (coinbase/api-get *coinbase-product-url* "/loans/options"))

(define (coinbase-post-loans-repay-interest idem from-profile-id currency native-amount)
  (coinbase/api-post *coinbase-product-url* "/loans/repay-interest"
                     (scm->json-string `((idem . ,idem)
                                         (from_profile_id . ,from-profile-id)
                                         (currency . ,currency)
                                         (native_amount . ,native-amount)))))

(define (coinbase-post-loans-repay-principal loan-id idem from-profile-id currency native-amount)
  (coinbase/api-post *coinbase-product-url* "/loans/repay-principal"
                     (scm->json-string `((loan_id . ,loan-id)
                                         (idem . ,idem)
                                         (from_profile_id . ,from-profile-id)
                                         (currency . ,currency)
                                         (native_amount . ,native-amount)))))

(define (coinbase-get-loans-repayment-preview)
  (coinbase/api-get *coinbase-product-url* "/loans/repayment-preview"))

;; Futures

(define (coinbase-get-margin-auto-loan)
  (coinbase/api-get *coinbase-product-url* "/margin/auto-loan"))

(define (coinbase-post-margin-auto-loan auto-loan)
  (coinbase/api-post *coinbase-product-url* "/margin/auto-loan"
                     (scm->json-string `((auto_loan . ,auto-loan)))))

(define (coinbase-get-margin-usdc)
  (coinbase/api-get *coinbase-product-url* "/margin/usdc"))

(define (coinbase-post-margin-usdc enabled)
  (coinbase/api-post *coinbase-product-url* "/margin/usdc"
                     (scm->json-string `((enabled . ,enabled)))))

;; Coinbase price oracle

(define (coinbase-get-oracle)
  (coinbase/api-get *coinbase-product-url* "/oracle"))

;; Products

(define (coinbase-get-products)
  (coinbase/api-get *coinbase-product-url* "/products"))

(define (coinbase-get-products-volume-summary)
  (coinbase/api-get *coinbase-product-url* "/products/volume-summary"))

(define (coinbase-get-products-id pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/products/~a" pid)))

(define (coinbase-get-products-id-book pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/products/~a/book" pid)))

(define (coinbase-get-products-id-candles pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/products/~a/candles" pid)))

(define (coinbase-get-products-id-stats pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/products/~a/stats" pid)))

(define (coinbase-get-products-id-ticker pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/products/~a/ticker" pid)))

(define (coinbase-get-products-id-trades pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/products/~a/trades" pid)))

;; Profiles

(define (coinbase-get-profiles)
  (coinbase/api-get *coinbase-product-url* "/profiles"))

(define (coinbase-post-profiles name)
  (coinbase/api-post *coinbase-product-url* "/profiles"
                     (scm->json-string `((name . ,name)))))

(define (coinbase-post-profiles-transfer from to currency amount)
  (coinbase/api-post *coinbase-product-url* "/profiles/transfer"
                     (scm->json-string `((from . ,from)
                                         (to . ,to)
                                         (currency . ,currency)
                                         (amount . ,amount)))))

(define (coinbase-get-profiles-id pid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/profiles/~a" pid)))

(define (coinbase-put-profiles-id pid name)
  (coinbase/api-put *coinbase-product-url*
                    (format #f "/profiles/~a" pid)
                    (scm->json-string `((profile_id . ,pid)
                                        (name . ,name)))))

(define (coinbase-put-profiles-id-deactivate pid to)
  (coinbase/api-put *coinbase-product-url*
                    (format #f "/profiles/~a/deactivate" pid)
                    (scm->json-string `((profile_id . ,pid)
                                        (to . ,to)))))

;; Reports

(define (coinbase-get-reports)
  (coinbase/api-get *coinbase-product-url* "/reports"))

(define (coinbase-post-reports type year format email profile-id balance fills account otc-fills tax-invoice rfq-fills)
  (coinbase/api-post *coinbase-product-url* "/reports"
                     (scm->json-string `((type . ,type)
                                         (year . ,year)
                                         (format . ,format)
                                         (email . ,email)
                                         (profile_id . ,profile-id)
                                         (balance ((datetime . ,(current-time))
                                                   (group_by_profile . #f)))
                                         (fills ((start_date . ,(current-time))
                                                 (end_date . ,(current-time))
                                                 (product_id . ,fills)))
                                         (account ((start_date . ,(current-time))
                                                   (end_date . ,(current-time))
                                                   (account_id . ,account)))
                                         (otc-fills ((start_date . ,(current-time))
                                                     (end_date . ,(current-time))
                                                     (product_id . ,otc-fills)))
                                         (tax-invoice ((start_date . ,(current-time))
                                                       (end_date . ,(current-time))
                                                       (product_id . ,tax-invoice)))
                                         (rfq-fills ((start_date . ,(current-time))
                                                     (end_date . ,(current-time))
                                                     (product_id . ,rfq-fills)))))))

(define (coinbase-get-reports-id rid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/reports/~a" rid)))

;; Travel rules

(define (coinbase-get-travel-rules)
  (coinbase/api-get *coinbase-product-url* "/travel-rules"))

(define (coinbase-post-travel-rules address orig-name orig-country)
  (coinbase/api-post *coinbase-product-url* "/travel-rules"
                     (scm->json-string `((address . ,address)
                                         (originator_name . ,orig-name)
                                         (originator_country . ,orig-country)))))

(define (coinbase-delete-travel-rules-id id)
  (coinbase/api-delete *coinbase-product-url*
                       (format #f "/travel-rules/~a" id)))

;; Users

(define (coinbase-get-users-id-exchange-limits uid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/users/~a/exchange-limits" uid)))

(define (coinbase-post-users-id-settlement-preferences settle-pref user-id)
  (coinbase/api-post *coinbase-product-url*
                     (format #f "/users/~a/settlement-preferences" user-id)
                     (scm->json-string `((settlement_preference . ,settle-pref)
                                         (user_id . ,user-id)))))

(define (coinbase-get-users-id-trading-volumes uid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/users/~a/trading-volumes" uid)))

;; Wrapped assets

(define (coinbase-get-wrapped-assets)
  (coinbase/api-get *coinbase-product-url* "/wrapped-assets"))

(define (coinbase-get-wrapped-assets-stake-wrap)
  (coinbase/api-get *coinbase-product-url* "/wrapped-assets/stake-wrap"))

(define (coinbase-post-wrapped-assets-stake-wrap from-currency to-currency amount)
  (coinbase/api-post *coinbase-product-url* "/wrapped-assets/stake-wrap"
                     (scm->json-string `((from_currency . ,from-currency)
                                         (to_currency . ,to-currency)
                                         (amount . ,amount)))))

(define (coinbase-get-wrapped-assets-stake-wrap-id sid)
  (coinbase/api-get *coinbase-product-url*
                    (format #f "/wrapped-assets/stake-wrap/~a" sid)))
