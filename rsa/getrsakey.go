package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"

	"github.com/Bifang-Bird/goEncrypt"
)

/*
	Asymmetric encryption requires the generation of a pair of keys rather than a key, so before encryption here you need to get a pair of keys, public and private, respectively
	Generate the public and private keys all at once
		Encryption: plaintext to the power E Mod N to output ciphertext
		Decryption: ciphertext to the power D Mod N outputs plaintext

		Encryption operations take a long time? Encryption is faster

		The data is encrypted and cannot be easily decrypted
*/

type RsaKey struct {
	PrivateKey string
	PublicKey  string
}

func GenerateRsaKeyHex(bits int) (RsaKey, error) {
	if bits != 1024 && bits != 2048 {
		return RsaKey{}, goEncrypt.ErrRsaBits
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RsaKey{}, err
	}
	return RsaKey{
		PrivateKey: hex.EncodeToString(x509.MarshalPKCS1PrivateKey(privateKey)),
		PublicKey:  hex.EncodeToString(x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)),
	}, nil
}

func GenerateRsa8KeyHex(bits int) (RsaKey, error) {
	if bits != 1024 && bits != 2048 {
		return RsaKey{}, goEncrypt.ErrRsaBits
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RsaKey{}, err
	}
	privateKey8, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicKey8, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	return RsaKey{
		PrivateKey: hex.EncodeToString(privateKey8),
		PublicKey:  hex.EncodeToString(publicKey8),
	}, nil
}

func GenerateRsaKeyBase64(bits int) (RsaKey, error) {
	if bits != 1024 && bits != 2048 {
		return RsaKey{}, goEncrypt.ErrRsaBits
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RsaKey{}, err
	}
	return RsaKey{
		PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privateKey)),
		PublicKey:  base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)),
	}, nil
}

func GenerateRsa8KeyBase64(bits int) (RsaKey, error) {
	if bits != 1024 && bits != 2048 {
		return RsaKey{}, goEncrypt.ErrRsaBits
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RsaKey{}, err
	}
	//x509.MarshalPKCS1PrivateKey(privateKey)
	privateKey8, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicKey8, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	return RsaKey{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey8),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey8),
	}, nil
}
