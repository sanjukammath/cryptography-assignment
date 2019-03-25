package main

import (
	"crypto/aes"
	"crypto/cipher"
	. "cryptography-assignment/ca-util"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

type SecureMessage struct {
	EncryptedMessage []byte `json:"encryptedMessage"`
	EncryptedAESK    []byte `json:"encryptedAESK"`
}

type Message struct {
	Data      Info   `json:"Message"`
	Signature []byte `json:"Signature"`
	PubKey    []byte `json:"pubKey"`
}

type Info struct {
	Value     string `json:"info"`
	WrittenBy string `json:"writtenBy"`
}

func main() {
	http.HandleFunc("/requestComms", commsRequestHandler)
	http.HandleFunc("/message", messageHandler)
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func commsRequestHandler(w http.ResponseWriter, r *http.Request) {
	key := GenerateKeys()

	publicKey := key.PublicKey
	publicKeyBytes := PublicKeyToBytes(&publicKey)

	w.Write(publicKeyBytes)
}

func messageHandler(w http.ResponseWriter, r *http.Request) {

	secureMessageBytes, err := ioutil.ReadAll(r.Body)

	var secureMessage SecureMessage
	err = json.Unmarshal(secureMessageBytes, &secureMessage)
	CheckError(err)

	encryptedAESK := secureMessage.EncryptedAESK
	ciphertext := secureMessage.EncryptedMessage

	path, err := filepath.Abs("store/keys/self/private.pem")
	privateKeyBytes, err := ioutil.ReadFile(path)
	CheckError(err)

	privateKey := BytesToPrivateKey(privateKeyBytes)

	passPhrase := DecryptWithPrivateKey(encryptedAESK, privateKey)

	c, err := aes.NewCipher(passPhrase)
	CheckError(err)

	gcm, err := cipher.NewGCM(c)
	CheckError(err)

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}

	var message Message

	err = json.Unmarshal(plaintext, &message)

	fmt.Println(message.Data)
}
