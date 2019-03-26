package cautil

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCheckError(t *testing.T) {
	t.Logf("Running test case: %s", "Returns normally when error is nil")
	CheckError(nil)

	t.Logf("Running test case: %s", "Exits when non nil error is present")
	if os.Getenv("BE_CRASHER") == "1" {
		CheckError(errors.New("unit testing"))
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCheckError")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestPrivateKeyToBytes(t *testing.T) {
	t.Logf("Running test case: %s", "Converts Private Key to Bytes")
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)
	PrivateKeyToBytes(key)
}

func TestPublicKeyToBytes(t *testing.T) {
	t.Logf("Running test case: %s", "Converts Public Key to Bytes")
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)
	PublicKeyToBytes(&key.PublicKey)
}

func TestBytesToPrivateKey(t *testing.T) {
	t.Logf("Running test case: %s", "Converts Bytes to Private Key")
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)
	privateKeyBytes := PrivateKeyToBytes(key)

	BytesToPrivateKey(privateKeyBytes)
}

func TestBytesToPublicKey(t *testing.T) {
	t.Logf("Running test case: %s", "Converts Bytes to Public Key")
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)
	publicKeyBytes := PublicKeyToBytes(&key.PublicKey)

	BytesToPublicKey(publicKeyBytes)
}

func TestEncryptWithPublicKey(t *testing.T) {
	t.Logf("Running test case: %s", "Encrypts with Public Key")
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)

	EncryptWithPublicKey([]byte(`{"Message": "This is the Message"}`), &key.PublicKey)
}

func TestDecryptWithPrivateKey(t *testing.T) {
	t.Logf("Running test case: %s", "Decrypts with Private Key")
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, BITSIZE)
	CheckError(err)

	cipherText := EncryptWithPublicKey([]byte(`{"Message": "This is the Message"}`), &key.PublicKey)

	data := DecryptWithPrivateKey(cipherText, key)

	t.Logf("Running test case: %s", "Data retrieved after decryption")
	want := []byte(`{"Message": "This is the Message"}`)
	got := data

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Retrieved wrong message: got %v want %v", want, got)
	}
}

func TestGenerateKeys(t *testing.T) {
	t.Logf("Running test case: %s", "Generates Keys and writes them at appropriate paths")
	GenerateKeys()
	path, err := filepath.Abs("store/keys/self/private.pem")
	CheckError(err)
	ioutil.ReadFile(path)
	path, err = filepath.Abs("store/keys/self/public.pem")
	CheckError(err)
	ioutil.ReadFile(path)
}

func TestSignHash(t *testing.T) {
	t.Logf("Running test case: %s", "Signs Hash")
	key := GenerateKeys()

	SignHash(key, [64]byte{})
}

func TestGetPublicKey(t *testing.T) {
	t.Logf("Running test case: %s", "Gets Public Key from url")
	GetPublicKey("http://localhost:3000/requestComms")
}
