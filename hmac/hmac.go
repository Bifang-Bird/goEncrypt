package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

func HmacSignSha256(secret string, datas string) (string, error) {
	if len(secret) <= 0 || len(datas) <= 0 {
		return "", errors.New("缺少参数")
	}
	key := []byte(secret)
	data := []byte(datas)
	h := hmac.New(sha256.New, key)
	h.Write(data)
	sign := hex.EncodeToString(h.Sum(nil))
	return sign, nil
}

func HmacVerifySignSha256(originSign string, secret string, datas string) bool {
	if len(secret) <= 0 || len(datas) <= 0 || len(originSign) <= 0 {
		return false
	}

	sign, err := HmacSignSha256(secret, datas)
	if err != nil {
		return false
	}

	if !strings.EqualFold(sign, originSign) {
		return false
	}

	return true
}
