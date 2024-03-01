package main

import (
	"acme-mock/acme"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"time"
)

////
// Types
////

type acmeFn func(http.ResponseWriter, *http.Request) interface{}

type orderCtx struct {
	obj *acme.Order
	crt []byte
}

type jwsobj struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type authzResponse struct {
	Status     string      `json:"status"`
	Expires    string      `json:"expires"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Challenge struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Status    string `json:"status"`
	Validated string `json:"validated"`
	Token     string `json:"token"`
}

////
// Variables & Constants
////

const (
	directoryPath  = "/directory"
	newNoncePath   = "/new-nonce"
	newAccountPath = "/new-account"
	newOrderPath   = "/new-order"
	revokeCertPath = "/revoke-cert"
	keyChangePath  = "/key-change"
	authzPath      = "/authz"

	finalizePath    = "/finalize/"
	certificatePath = "/certificate/"
	orderPath       = "/order/"
)

var (
	httpsAddr = flag.String("a", ":443", "address used for HTTPS socket")
	tlsKey    = flag.String("k", "", "TLS private key")
	tlsCert   = flag.String("c", "", "TLS certificate")
	rsaBits   = flag.Int("b", 2048, "RSA key size")
)

var key *rsa.PrivateKey
var caKey *rsa.PrivateKey
var orders []*orderCtx
var ordersMtx sync.Mutex

////
// Utility functions
////

func createCrt(csrMsg *acme.CSRMessage) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(csrMsg.Csr)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return nil, err
	}

	caTemp := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Mock CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1), // Valid for 1 day
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCert, _ := x509.CreateCertificate(rand.Reader, &caTemp, &caTemp, &caKey.PublicKey, key)

	certTemp := x509.Certificate{
		SerialNumber:   big.NewInt(5),
		Subject:        csr.Subject,
		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		IPAddresses:    csr.IPAddresses,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, 1), // Valid for 1 day
	}

	crt, err := x509.CreateCertificate(rand.Reader, &certTemp, &caTemp, &key.PublicKey, caKey)

	// combinedCerts := append(crt, caCert...)
	// if err != nil {
	// 	return nil, err
	// }

	// Encode the certificates to PEM format
	pemCert1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert})
	pemCert2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt})

	// Concatenate the PEM-encoded certificates
	fullChain := append(pemCert1, pemCert2...)

	// Convert to string for demonstration
	fullChainString := string(fullChain)

	// Print the concatenated PEM-encoded certificates
	fmt.Println(fullChainString)

	fmt.Println(err)

	return fullChain, err
}

func getRandomNonce() string {
	length := 22

	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randomBytes := make([]byte, length)

	// Determine the number of random bytes needed
	numLetters := byte(len(letters))

	// Fill the byte slice with random data
	_, err := rand.Read(randomBytes)
	if err != nil {
		return ""
	}

	// Convert random bytes to letters
	for i, b := range randomBytes {
		randomBytes[i] = letters[b%numLetters]
	}

	return string(randomBytes)
}

func getOrder(r *http.Request) (*orderCtx, error) {
	id, err := strconv.Atoi(path.Base(r.URL.Path))
	if err != nil {
		return nil, err
	}

	ordersMtx.Lock()
	defer ordersMtx.Unlock()

	if id < len(orders) {
		return orders[id], nil
	} else {
		return nil, fmt.Errorf("order not found")
	}
}

func createURL(r *http.Request, path string) string {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
	r.URL.Path = path

	return r.URL.String()
}

////
// Handlers
////

func directoryHandler(w http.ResponseWriter, r *http.Request) interface{} {

	return acme.Directory{
		NewNonceURL:   createURL(r, newNoncePath),
		NewAccountURL: createURL(r, newAccountPath),
		NewOrderURL:   createURL(r, newOrderPath),
		RevokeCertURL: createURL(r, revokeCertPath),
		KeyChangeURL:  createURL(r, keyChangePath),
		NewAuthzURL:   createURL(r, authzPath),
	}
}

func nonceHandler(w http.ResponseWriter, r *http.Request) {
	// Hardcoded value copied from RFC 8555
	//w.Header().Add("Replay-Nonce", "oFvnlFP1wIhRlYS2jTaXbA")
	w.Header().Add("Replay-Nonce", getRandomNonce())

	w.Header().Add("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func accountHandler(w http.ResponseWriter, r *http.Request) interface{} {
	return acme.Account{
		Status: acme.StatusValid,
		Orders: createURL(r, "orders"),
	}
}

func newOrderHandler(w http.ResponseWriter, r *http.Request) interface{} {
	var order acme.Order
	err := json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return nil
	}

	ordersMtx.Lock()
	orderId := strconv.Itoa(len(orders))
	orders = append(orders, &orderCtx{&order, nil})
	ordersMtx.Unlock()

	order.Finalize = createURL(r, path.Join(finalizePath, orderId))

	mockChallengeURL := "https://localhost:8443/authz"
	order.Authorizations = []string{mockChallengeURL}

	orderURL := createURL(r, path.Join(orderPath, orderId))
	w.Header().Add("Location", orderURL)
	w.Header().Add("Replay-Nonce", getRandomNonce())

	w.WriteHeader(http.StatusCreated)
	return order
}

func finalizeHandler(w http.ResponseWriter, r *http.Request) interface{} {
	id := path.Base(r.URL.Path)
	order, err := getOrder(r)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return nil
	}

	var csrMsg acme.CSRMessage
	err = json.NewDecoder(r.Body).Decode(&csrMsg)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return nil
	}

	order.crt, err = createCrt(&csrMsg)
	if err != nil {
		http.Error(w, "createCrt failed", http.StatusInternalServerError)
		return nil
	}

	order.obj.Status = acme.StatusValid
	order.obj.Certificate = createURL(r, path.Join(certificatePath, id))

	orderURL := createURL(r, path.Join(orderPath, id))
	w.Header().Add("Location", orderURL)
	w.Header().Add("Replay-Nonce", getRandomNonce())

	return order.obj
}

func orderHandler(w http.ResponseWriter, r *http.Request) interface{} {
	order, err := getOrder(r)
	w.Header().Add("Replay-Nonce", getRandomNonce())

	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return nil
	}

	return order.obj
}

func certHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Replay-Nonce", getRandomNonce())

	order, err := getOrder(r)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Write(order.crt)

	// err = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: order.crt})
	// if err != nil {
	// 	http.Error(w, "PEM encoding failed", http.StatusInternalServerError)
	// 	return
	// }
}

////
// Middleware
////

func authzHandler(w http.ResponseWriter, r *http.Request) interface{} {

	// Get the current date and time
	currentTime := time.Now().UTC()

	// Format the current date and time as strings
	currentTimeString := currentTime.Format(time.RFC3339)

	// Create a authzResponse object
	resp := authzResponse{
		Status:  "valid",
		Expires: currentTimeString,
		Identifier: Identifier{
			Type:  "dns",
			Value: "localhost",
		},
		Challenges: []Challenge{
			{
				Type:      "http-01",
				URL:       createURL(r, "/chall"),
				Token:     getRandomNonce(),
				Status:    "valid",
				Validated: currentTimeString,
			},
		},
	}

	// Set the Content-Type header
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", getRandomNonce())

	// Set the status code to 201
	w.WriteHeader(http.StatusCreated)

	return resp
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
			http.Error(w, "JSON encoding failed", http.StatusInternalServerError)
			return
		}
	})
}

func jsonMiddlewareNewAccount(fn acmeFn) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Location", createURL(r, "new-account"))
		w.Header().Add("Replay-Nonce", getRandomNonce())
		w.WriteHeader(http.StatusCreated)

		val := fn(w, r)
		if val == nil {
			return
		}

		err := json.NewEncoder(w).Encode(val)
		if err != nil {
			http.Error(w, "JSON encoding failed", http.StatusInternalServerError)
			return
		}
	})
}

func jwtMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var jws jwsobj
		err := json.NewDecoder(r.Body).Decode(&jws)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			http.Error(w, "Invalid Base64", http.StatusBadRequest)
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(payload))
		h.ServeHTTP(w, r)
	})
}

////
// main
////

func main() {
	flag.Parse()
	if *tlsKey == "" || *tlsCert == "" {
		fmt.Fprintf(flag.CommandLine.Output(), "missing TLS key or certificate\n")
		flag.Usage()
		os.Exit(2)
	}

	var err error
	key, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	caKey, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle(directoryPath, jsonMiddleware(directoryHandler))
	http.HandleFunc(newNoncePath, nonceHandler)
	http.Handle(newAccountPath, jsonMiddlewareNewAccount(accountHandler))
	http.Handle(newOrderPath, jwtMiddleware(jsonMiddleware(newOrderHandler)))
	http.Handle(finalizePath, jwtMiddleware(jsonMiddleware(finalizeHandler)))
	http.HandleFunc(certificatePath, certHandler)
	http.Handle(orderPath, jsonMiddleware(orderHandler))
	http.Handle(authzPath, jsonMiddleware(authzHandler))
	log.Fatal(http.ListenAndServeTLS(*httpsAddr, *tlsCert, *tlsKey, nil))
}
