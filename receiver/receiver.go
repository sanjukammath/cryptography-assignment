package main

import (
	"crypto/rand"
	"crypto/rsa"
	. "cryptography-assignment/ca-util"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

const (
	BITSIZE int = 2048
)

type response struct {
	Ready bool `json:"ready"`
}

func main() {
	http.HandleFunc("/requestComms", commsRequestHandler)
	http.HandleFunc("/message", commsRequestHandler)
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func commsRequestHandler(w http.ResponseWriter, r *http.Request) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)

	privateKeyBytes := PrivateKeyToBytes(key)
	path, err := filepath.Abs("store/keys/self/private.pem")
	err = ioutil.WriteFile(path, privateKeyBytes, 0600)
	CheckError(err)

	publicKey := key.PublicKey
	publicKeyBytes := PublicKeyToBytes(&publicKey)
	path, err = filepath.Abs("store/keys/self/public.pem")
	err = ioutil.WriteFile(path, publicKeyBytes, 0644)
	CheckError(err)

	w.Write(publicKeyBytes)
}

func messageHandler(w http.ResponseWriter, r *http.Request) {

}
