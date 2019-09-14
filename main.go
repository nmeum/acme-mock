package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/nmeum/acme-mock/acme"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"strconv"
	"sync"
)

type acmeFn func(http.ResponseWriter, *http.Request) interface{}

const (
	directoryPath  = "/directory"
	newNoncePath   = "/new-nonce"
	newAccountPath = "/new-account"
	newOrderPath   = "/new-order"
	revokeCertPath = "/revoke-cert"
	keyChangePath  = "/key-change"

	finalizePath    = "/finalize/"
	certificatePath = "/certificate/"
	orderPath       = "/order/"
)

var (
	httpsAddr = flag.String("a", ":443", "address used for HTTPS socket")
	tlsKey    = flag.String("k", "", "TLS private key")
	tlsCert   = flag.String("c", "", "TLS certificate")
)

var orders []*orderCtx
var ordersMtx sync.Mutex

type orderCtx struct {
	obj *acme.Order
	crt []byte
}

type jwsobj struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func getOrder(r *http.Request) (*orderCtx, error) {
	id, err := strconv.Atoi(path.Base(r.URL.Path))
	if err != nil {
		return nil, err
	}

	ordersMtx.Lock()
	if id >= len(orders) {
		ordersMtx.Unlock()
		return nil, nil
	}

	order := orders[id]
	ordersMtx.Unlock()

	return order, nil
}

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
	return acme.Account{
		Status: "valid",
		Orders: baseURLpath(r, "orders"),
	}
}

func newOrderHandler(w http.ResponseWriter, r *http.Request) interface{} {
	var order acme.Order
	err := json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		panic(err)
	}

	ordersMtx.Lock()
	orderId := strconv.Itoa(len(orders))
	orders = append(orders, &orderCtx{&order, nil})
	ordersMtx.Unlock()

	order.Finalize = baseURLpath(r, path.Join(finalizePath, orderId))
	order.Authorizations = []string{}

	orderURL := baseURLpath(r, path.Join(orderPath, orderId))
	w.Header().Add("Location", orderURL)

	w.WriteHeader(http.StatusCreated)
	return order
}

func finalizeHandler(w http.ResponseWriter, r *http.Request) interface{} {
	id := path.Base(r.URL.Path)

	order, err := getOrder(r)
	if order == nil && err == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return nil
	}

	order.crt = []byte("TODO")
	order.obj.Status = acme.StatusValid
	order.obj.Certificate = baseURLpath(r, path.Join(certificatePath, id))

	orderURL := baseURLpath(r, path.Join(orderPath, id))
	w.Header().Add("Location", orderURL)

	return order
}

func jsonMiddleware(fn acmeFn) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		val := fn(w, r)
		if val == nil {
			return
		}

		err := json.NewEncoder(w).Encode(val)
		if err != nil {
			panic(err)
		}
	})
}

func jwtMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var jws jwsobj
		err := json.NewDecoder(r.Body).Decode(&jws)
		if err != nil {
			panic(err)
		}

		payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			panic(err)
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(payload))
		h.ServeHTTP(w, r)
	})
}

func main() {
	flag.Parse()

	http.Handle(directoryPath, jsonMiddleware(directoryHandler))
	http.HandleFunc(newNoncePath, nonceHandler)
	http.Handle(newAccountPath, jsonMiddleware(accountHandler))
	http.Handle(newOrderPath, jwtMiddleware(jsonMiddleware(newOrderHandler)))
	http.Handle(finalizePath, jwtMiddleware(jsonMiddleware(finalizeHandler)))
	log.Fatal(http.ListenAndServeTLS(*httpsAddr, *tlsCert, *tlsKey, nil))
}
