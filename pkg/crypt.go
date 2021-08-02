package mycrypt

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
)

type Encryption interface {
	Dec(encString string) (string, error)
	Enc(secretString string) (string, error)
}

type encryption struct {
	mySecretString     string
	prefix, passphrase string
	secretKeyring      string
	publicKeyring      string
}

func NewEncWithOptins(mySecretString, prefix, passphrase, secretKeyring, publicKeyring string) Encryption {

	e := encryption{
		mySecretString: mySecretString,
		prefix:         prefix,
		passphrase:     passphrase,
		secretKeyring:  secretKeyring,
		publicKeyring:  publicKeyring,
	}
	return &e
}

func (e encryption) Dec(encString string) (string, error) {

	log.Println("Secret Keyring:", e.secretKeyring)
	log.Println("Passphrase:", "****")

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(e.secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	// Get the passphrase and read the private key.
	passphraseByte := []byte(e.passphrase)
	log.Println("Decrypting private key using passphrase")
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}
	log.Println("Finished decrypting private key using passphrase")

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}

func (e encryption) Enc(secretString string) (string, error) {
	log.Println("Secret to hide:", "****")
	log.Println("Public Keyring:", e.publicKeyring)

	// Read in public key
	keyringFileBuffer, _ := os.Open(e.publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}

	// encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(secretString))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	// Encode to base64
	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	// Output encrypted/encoded string
	log.Println("Encrypted Secret:", encStr)

	return encStr, nil
}
