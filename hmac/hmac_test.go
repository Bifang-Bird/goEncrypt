package hmac

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	msg        = "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	key        = "123456789"
	originSign = "123456"
)

func TestHmacSignSha256(t *testing.T) {

	// good
	sign, err := HmacSignSha256(key, msg)

	if err != nil {

	}

	fmt.Println(sign)

	//good
	bools := HmacVerifySignSha256(sign, key, msg)
	assert.Nil(t, err)
	assert.Equal(t, bools, true)
	//bad
	boolss := HmacVerifySignSha256(originSign, key, msg)
	assert.Nil(t, err)
	assert.Equal(t, boolss, false)
}
