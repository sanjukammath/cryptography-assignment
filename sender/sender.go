package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	. "cryptography-assignment/ca-util"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	info := &Info{"This is a Secret Message", "Written By Sanjay S B"}
	infoBytes, err := json.Marshal(info)
	CheckError(err)

	checksum := sha512.Sum512(infoBytes)
	rsaKey := GenerateKeys()
	signature := SignHash(rsaKey, checksum)

	publicKey := rsaKey.PublicKey
	publicKeyBytes := PublicKeyToBytes(&publicKey)
	message := &Message{*info, signature, publicKeyBytes}
	messageBytes, err := json.Marshal(message)
	CheckError(err)

	recieverKey := GetPublicKey("http://localhost:3000/requestComms")

	key := []byte("32byteslongsecretpassphrase!1234")
	c, err := aes.NewCipher(key)
	CheckError(err)
	gcm, err := cipher.NewGCM(c)
	CheckError(err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	CheckError(err)

	encryptedMessage := gcm.Seal(nonce, nonce, messageBytes, nil)
	encryptedAESK := EncryptWithPublicKey(key, recieverKey)

	secureMessage := &SecureMessage{encryptedMessage, encryptedAESK}

	secureMessageBytes, err := json.Marshal(secureMessage)
	CheckError(err)

	req, err := http.NewRequest("POST", "http://localhost:3000/message", bytes.NewReader(secureMessageBytes))
	CheckError(err)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
}
