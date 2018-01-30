package secure

import (
	"github.com/speps/go-hashids"
)

type HashidsEncoder struct{
	baseEncoder

	params *hashids.HashIDData
}

func newHashidsEncoder() *HashidsEncoder {
	return &HashidsEncoder{baseEncoder{isa: MethodHashids}, hashids.NewData()}
}
func(enc HashidsEncoder) SetKey(key string) SecureEncoder {
	enc.key = []byte(key)
	enc.params.Salt = key
	return enc
}

// Encrypt string to base64 crypto using AES
func(enc HashidsEncoder) Encrypt(text string) (string, error) {
	plaintext := []byte(text)
	codec := hashids.NewWithData(enc.params)

	ints := make([]int64, len(plaintext))
	for i, s := range plaintext {
		ints[i] = int64(s)
	}
	result, err := codec.EncodeInt64(ints)
	return result, err
}

// Decrypt from base64 to decrypted string
func(enc HashidsEncoder) Decrypt(cryptoText string) (string, error) {
	result := ""
	codec := hashids.NewWithData(enc.params)

	arr, err := codec.DecodeInt64WithError(cryptoText)
	if err != nil {
		return "", err
	}
	for _, x := range arr {
		result += string(x)
	}
	return result, err
}
