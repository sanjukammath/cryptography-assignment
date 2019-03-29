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
	"os"
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
	CheckError(err)

	var secureMessage SecureMessage
	err = json.Unmarshal(secureMessageBytes, &secureMessage)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

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
	CheckError(err)

	var message Message

	err = json.Unmarshal(plaintext, &message)
	CheckError(err)

	senderPubKey := message.PubKey

	storeSenderKey(senderPubKey)

	fmt.Println(message.Data)
}

func storeSenderKey(senderPubKey []byte) {
	path, err := filepath.Abs("store/keys/sender/public.pem")

	os.MkdirAll(filepath.Dir(path), 0644)
	err = ioutil.WriteFile(path, senderPubKey, 0644)
	CheckError(err)

}
