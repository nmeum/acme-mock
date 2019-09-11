package main

import (
	"encoding/json"
	"flag"
	"github.com/xenolf/lego/acme"
	"log"
	"net/http"
)

type acmeFn func(http.ResponseWriter, *http.Request) interface{}

const (
	newNoncePath   = "/new-nonce"
	newAccountPath = "/new-account"
	newOrderPath   = "/new-order"
	revokeCertPath = "/revoke-cert"
	keyChangePath  = "/key-change"
)

var (
	httpsAddr = flag.String("a", ":443", "address used for HTTPS socket")
	tlsKey    = flag.String("k", "", "TLS private key")
	tlsCert   = flag.String("c", "", "TLS certificate")
)

func baseURLpath(r *http.Request, path string) string {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
	r.URL.Path = path

	return r.URL.String()
}

func directoryHandler(w http.ResponseWriter, r *http.Request) interface{} {
	return acme.Directory{
		NewNonceURL:   baseURLpath(r, newNoncePath),
		NewAccountURL: baseURLpath(r, newAccountPath),
		NewOrderURL:   baseURLpath(r, newOrderPath),
		RevokeCertURL: baseURLpath(r, revokeCertPath),
		KeyChangeURL:  baseURLpath(r, keyChangePath),
	}
}

func nonceHandler(w http.ResponseWriter, r *http.Request) {
	// Hardcoded value copied from RFC 8555
	w.Header().Add("Replay-Nonce", "oFvnlFP1wIhRlYS2jTaXbA")

	w.Header().Add("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func accountHandler(w http.ResponseWriter, r *http.Request) interface{} {
	w.Header().Add("Location", baseURLpath(r, "account"))

	return acme.Account{
		Status: "valid",
		Orders: path.Join(base, "orders"),
	}
}

func jsonMiddleware(fn acmeFn) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		val := fn(w, r)
		err := json.NewEncoder(w).Encode(val)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func main() {
	flag.Parse()

	http.Handle("/directory", jsonMiddleware(directoryHandler))
	http.HandleFunc(newNoncePath, nonceHandler)
	http.Handle(newAccountPath, jsonMiddleware(accountHandler))
	log.Fatal(http.ListenAndServeTLS(*httpsAddr, *tlsCert, *tlsKey, nil))
}
