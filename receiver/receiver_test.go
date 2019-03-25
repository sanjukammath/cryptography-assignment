package main

import (
	"crypto/rsa"
	"crypto/x509"
	. "cryptography-assignment/ca-util"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCommsRequestHandler(t *testing.T) {
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
		CheckError(errors.New("not ok"))
	}
}

func TestMessageHandler(t *testing.T) {
	req, err := http.NewRequest("POST", "/message", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(messageHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
