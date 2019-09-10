package main

import (
	"encoding/json"
	"flag"
	"github.com/xenolf/lego/acme"
	"log"
	"net/http"
	"path"
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

func directoryHandler(w http.ResponseWriter, r *http.Request) interface{} {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
	r.URL.Path = ""

	base := r.URL.String()
	return acme.Directory{
		NewNonceURL:   path.Join(base, newNoncePath),
		NewAccountURL: path.Join(base, newAccountPath),
		NewOrderURL:   path.Join(base, newOrderPath),
		RevokeCertURL: path.Join(base, revokeCertPath),
		KeyChangeURL:  path.Join(base, keyChangePath),
	}
}

func nonceHandler(w http.ResponseWriter, r *http.Request) {
	// Hardcoded value copied from RFC 8555
	w.Header().Add("Replay-Nonce", "oFvnlFP1wIhRlYS2jTaXbA")
	w.WriteHeader(http.StatusOK)
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
	log.Fatal(http.ListenAndServeTLS(*httpsAddr, *tlsCert, *tlsKey, nil))
}
