package cautil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const (
	BITSIZE int = 2048
)

func CheckError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	CheckError(err)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

func BytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		fmt.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)

	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	CheckError(err)
	return key
}

func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		fmt.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		CheckError(err)
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	CheckError(err)
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		CheckError(errors.New("not ok"))
	}
	return key
}

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	CheckError(err)
	return ciphertext
}

func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	CheckError(err)
	return plaintext
}

func GenerateKeys() *rsa.PrivateKey {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)

	privateKeyBytes := PrivateKeyToBytes(key)
	path, err := filepath.Abs("store/keys/self/private.pem")
	os.MkdirAll(filepath.Dir(path), 0644)
	err = ioutil.WriteFile(path, privateKeyBytes, 0600)
	CheckError(err)

	publicKey := key.PublicKey
	publicKeyBytes := PublicKeyToBytes(&publicKey)
	path, err = filepath.Abs("store/keys/self/public.pem")
	err = ioutil.WriteFile(path, publicKeyBytes, 0644)
	CheckError(err)

	return key
}

func SignHash(rsaKey *rsa.PrivateKey, checksum [64]byte) []byte {
	reader := rand.Reader
	signature, err := rsa.SignPKCS1v15(reader, rsaKey, crypto.SHA512, checksum[:])
	CheckError(err)

	return signature
}

func GetPublicKey(url string) *rsa.PublicKey {
	resp, err := http.Get(url)
	CheckError(err)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	CheckError(err)

	path, err := filepath.Abs("store/keys/receiver/public.pem")
	os.MkdirAll(filepath.Dir(path), 0644)
	err = ioutil.WriteFile(path, body, 0644)
	CheckError(err)

	recieverKey := BytesToPublicKey(body)

	return recieverKey
}
