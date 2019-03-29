package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	. "cryptography-assignment/ca-util"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestCommsRequestHandler(t *testing.T) {
	t.Logf("Running test case: %s", "CommsRequestHandler responds with a public key")
	req, err := http.NewRequest("GET", "/requestComms", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(commsRequestHandler)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	block, _ := pem.Decode(rr.Body.Bytes())
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		fmt.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		CheckError(err)
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	CheckError(err)
	_, ok := ifc.(*rsa.PublicKey)
	if !ok {
		t.Errorf("handler returned wrong data. want Public Key")
	}
}

func TestMessageHandler(t *testing.T) {
	t.Logf("Running test case: %s", "MessageHandler validates message")
	req, err := http.NewRequest("POST", "/message", bytes.NewReader([]byte{}))
	if err != nil {
		fmt.Println("Done")
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(messageHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}

func TestStoreSenderKey(t *testing.T) {
	t.Logf("Running test case: %s", "Store Sender key stores the Key")
	req, err := http.NewRequest("GET", "/requestComms", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(commsRequestHandler)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	storeSenderKey(rr.Body.Bytes())

	path, err := filepath.Abs("store/keys/sender/public.pem")
	CheckError(err)
	ioutil.ReadFile(path)
}
