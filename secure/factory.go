package secure

import "errors"

const (
	MethodAES     = "aes"
	MethodHashids = "hashids"
)

type SecureEncoder interface {
	Encrypt(origText string) (string, error)
	Decrypt(cryptoText string) (string, error)
	SetKey(key string) SecureEncoder
	Isa(name string) bool
}

type baseEncoder struct {
	SecureEncoder
	isa string
	key []byte
}

func (b baseEncoder) Isa(name string) bool {
	return b.isa == name
}

func EncryptFactory(method string) (SecureEncoder, error) {
	return func(method string) (SecureEncoder, error) {
		switch method {
		case MethodAES:
			return newAesEncoder(), nil
		case MethodHashids:
			return newHashidsEncoder(), nil
		}
		return nil, errors.New("not supported")
	}(method)
}

func NewAes() *AesEncoder {
	f, _ := EncryptFactory(MethodAES)
	return f.(*AesEncoder)
}

func NewHashids() *HashidsEncoder {
	f, _ := EncryptFactory(MethodHashids)
	return f.(*HashidsEncoder)
}
