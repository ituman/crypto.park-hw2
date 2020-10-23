package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	OpenCmd  = "open"
	CloseCmd = "close"
)

type SecretBox struct {
	privateKey  *rsa.PrivateKey
	outerPubKey *rsa.PublicKey
}

func (sb SecretBox) GetPublicKey() *rsa.PublicKey {
	return &sb.privateKey.PublicKey
}

func (sb *SecretBox) SetOuterPublicKey(pubKey *rsa.PublicKey) {
	sb.outerPubKey = pubKey
}

func NewSecretBox() *SecretBox {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &SecretBox{privateKey: key}
}

// Регистрация публичных ключей
func (sb *SecretBox) Register(reg *SecretBox) {
	fmt.Printf(
		"(registration) exchanged keys %x and %x \n\n",
		x509.MarshalPKCS1PublicKey(sb.GetPublicKey()),
		x509.MarshalPKCS1PublicKey(reg.GetPublicKey()),
	)
	sb.SetOuterPublicKey(reg.GetPublicKey())
	reg.SetOuterPublicKey(sb.GetPublicKey())
}

func (sb SecretBox) GenerateSig(data []byte) ([]byte, error) {

	digest := sha256.Sum256(data)

	signature, signErr := rsa.SignPKCS1v15(rand.Reader, sb.privateKey, crypto.SHA256, digest[:])

	if signErr != nil {
		return nil, fmt.Errorf("Could not sign message:%s", signErr.Error())
	}
	return signature, nil
}

func (sb SecretBox) verifySig(signature, data []byte) bool {

	digest := sha256.Sum256(data)
	b64sig := base64.StdEncoding.EncodeToString(signature)

	decodedSignature, _ := base64.StdEncoding.DecodeString(b64sig)

	verifyErr := rsa.VerifyPKCS1v15(sb.outerPubKey, crypto.SHA256, digest[:], decodedSignature)

	return verifyErr == nil
}

func (sb SecretBox) encrypt(msg []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		sb.outerPubKey,
		msg,
		nil,
	)
	if err != nil {
		panic(err)
	}

	return encryptedBytes
}

func (sb SecretBox) decrypt(encryptedBytes []byte) ([]byte, bool) {
	decryptedBytes, err := sb.privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	return decryptedBytes, err == nil
}

func (sb *SecretBox) Send(msg []byte) (secretMsg []byte, sign []byte) {
	secretMsg = sb.encrypt([]byte(msg))
	sign, _ = sb.GenerateSig(secretMsg)
	return secretMsg, sign
}

func (sb *SecretBox) Receive(secretMsg, sign []byte) (msg []byte, ok bool) {
	// Check sign
	signOK := sb.verifySig(sign, secretMsg)
	// Decrypt message
	msg, decryptOK := sb.decrypt(secretMsg)
	return msg, signOK && decryptOK
}

func main() {
	car := NewSecretBox()
	trinket := NewSecretBox()
	car.Register(trinket)

	// Sending command from trinket to car
	now := time.Now().Unix() // message "salt": expiration and different everytime (commands are not repeated)
	typeCmd := OpenCmd
	command := fmt.Sprintf("%s:%v", typeCmd, now)
	secretMsg, sign := trinket.Send([]byte(command))

	fmt.Printf(
		"(sending command) trinket -> car: encrypted message (%x), sign (%x)\n\n",
		secretMsg,
		sign,
	)

	fmt.Println("Sleep 5 seconds")
	time.Sleep(5 * time.Second)

	// Car gets the command
	msg, ok := car.Receive(secretMsg, sign)
	if !ok {
		panic("Hacking attempt!!!")
	}
	splitting := strings.Split(string(msg), ":")
	cmd, uTime := splitting[0], splitting[1]
	sendingTime, _ := strconv.Atoi(uTime)
	if time.Now().Unix()-int64(sendingTime) > 3 {
		panic("Hacking attempt!!!")
	}

	// All fine
	fmt.Println("(action) ", string(cmd), " - OK")

}
