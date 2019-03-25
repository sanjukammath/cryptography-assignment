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
	"io/ioutil"
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
	fmt.Println("the sender is coming up...")

	info := &Info{"This is a Secret Message", "Written By Sanjay S B"}
	infoBytes, err := json.Marshal(info)
	CheckError(err)

	checksum := sha512.Sum512(infoBytes)
	rsaKey := GenerateKeys()

	publicKey := rsaKey.PublicKey
	publicKeyBytes := PublicKeyToBytes(&publicKey)

	signature := SignHash(rsaKey, checksum)

	resp, err := http.Get("http://localhost:3000/requestComms")
	CheckError(err)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	CheckError(err)

	path, err := filepath.Abs("store/keys/receiver/public.pem")
	err = ioutil.WriteFile(path, body, 0644)
	CheckError(err)

	recieverKey := BytesToPublicKey(body)

	CheckError(err)

	key := []byte("passphrasewhichneedstobe32bytes!")

	c, err := aes.NewCipher(key)
	CheckError(err)

	encryptedAESK := EncryptWithPublicKey(key, recieverKey)

	gcm, err := cipher.NewGCM(c)
	CheckError(err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	CheckError(err)

	message := &Message{*info, signature, publicKeyBytes}

	messageBytes, err := json.Marshal(message)
	CheckError(err)
	encryptedMessage := gcm.Seal(nonce, nonce, messageBytes, nil)

	secureMessage := &SecureMessage{encryptedMessage, encryptedAESK}

	secureMessageBytes, err := json.Marshal(secureMessage)
	CheckError(err)

	req, err := http.NewRequest("POST", "http://localhost:3000/message", bytes.NewReader(secureMessageBytes))
	CheckError(err)

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ = ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))

}
