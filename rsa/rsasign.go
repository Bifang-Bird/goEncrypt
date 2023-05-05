package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"runtime"

	"github.com/Bifang-Bird/goEncrypt/hash"
	log "github.com/sirupsen/logrus"
)

func rsaSign8(msg, priKey []byte) (sign []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	//privateKey, err := x509.ParsePKCS1PrivateKey(priKey)
	privateKey8, err := x509.ParsePKCS8PrivateKey(priKey)

	privateKey := privateKey8.(*rsa.PrivateKey)

	hashed := hash.Sha1(msg)
	sign, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed)
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func rsaVerifySign8(msg []byte, sign []byte, pubKey []byte) bool {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	//publicKey, err := x509.ParsePKCS1PublicKey(pubKey)
	publicKey8, err := x509.ParsePKIXPublicKey(pubKey)
	publicKey := publicKey8.(*rsa.PublicKey)

	if err != nil {
		return false
	}
	hashed := hash.Sha1(msg)
	result := rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashed, sign)
	return result == nil
}

func RsaSign8Base64(msg []byte, base64PriKey string) (base64Sign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign8(msg, priBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

func RsaVerifySign8Base64(msg []byte, base64Sign, base64PubKey string) bool {
	signBytes, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return false
	}
	return rsaVerifySign8(msg, signBytes, pubBytes)
}

func RsaSign8Hex(msg []byte, hexPriKey string) (hexSign string, err error) {
	priBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign8(msg, priBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sign), nil
}

func RsaVerifySign8Hex(msg []byte, hexSign, hexPubKey string) bool {
	signBytes, err := hex.DecodeString(hexSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return false
	}
	return rsaVerifySign8(msg, signBytes, pubBytes)
}

func rsaSign(msg, priKey []byte) (sign []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	privateKey, err := x509.ParsePKCS1PrivateKey(priKey)
	hashed := hash.Sha256(msg)
	sign, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func rsaVerifySign(msg []byte, sign []byte, pubKey []byte) bool {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	publicKey, err := x509.ParsePKCS1PublicKey(pubKey)
	if err != nil {
		return false
	}
	hashed := hash.Sha256(msg)
	result := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, sign)
	return result == nil
}

func RsaSignBase64(msg []byte, base64PriKey string) (base64Sign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign(msg, priBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

func RsaVerifySignBase64(msg []byte, base64Sign, base64PubKey string) bool {
	signBytes, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return false
	}
	return rsaVerifySign(msg, signBytes, pubBytes)
}

func RsaSignHex(msg []byte, hexPriKey string) (hexSign string, err error) {
	priBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return "", err
	}
	sign, err := rsaSign(msg, priBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sign), nil
}

func RsaVerifySignHex(msg []byte, hexSign, hexPubKey string) bool {
	signBytes, err := hex.DecodeString(hexSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return false
	}
	return rsaVerifySign(msg, signBytes, pubBytes)
}
