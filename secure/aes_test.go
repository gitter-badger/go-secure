package secure_test

import (
	"testing"

	"github.com/mailoman/go-secure/secure"
	"github.com/stretchr/testify/suite"
)

type aesTestSuite struct {
	suite.Suite

	text            string
	textEncoded     string
	textEncodedFail string
	keyOk           string
	keyShort        string
}

func (ts *aesTestSuite) SetupSuite() {
	ts.text = "/myapi/test"
	ts.textEncoded = "KmiYwqbW0nUfhDS2zEDcazGLhk-XjEgfM8EN"
	ts.textEncodedFail = "116A47bJD9jZIUQsiNrWyC"
	ts.keyOk = "01234567891011121314151617181920"
	ts.keyShort = "0123"
}

func (ts *aesTestSuite) TestAesEncodedOk() {
	enc := secure.NewAes()
	ts.IsTypef(&secure.AesEncoder{}, enc, "Is AesEncoder object")

	encoded, err := enc.SetKey(ts.keyOk).Encrypt(ts.text)

	ts.Nilf(err, "No errors")
	ts.NotEmptyf(encoded, "Encoded ok")
}

func (ts *aesTestSuite) TestAesDecodedOk() {
	enc := secure.NewAes()
	ts.IsTypef(&secure.AesEncoder{}, enc, "Is AesEncoder object")

	decoded, err := enc.SetKey(ts.keyOk).Decrypt(ts.textEncoded)

	ts.Nilf(err, "No errors")
	ts.Equalf(ts.text, decoded, "Decoded ok")
}

func (ts *aesTestSuite) TestAesEncodeFail() {
	enc := secure.NewAes()
	ts.IsTypef(&secure.AesEncoder{}, enc, "Is AesEncoder object")

	encoded, err := enc.SetKey(ts.keyShort).Encrypt(ts.text)
	ts.EqualErrorf(err, "crypto/aes: invalid key size 4", "Is 'crypto/aes: invalid key size 4' error")
	ts.Equalf("", encoded, "Not encoded")
}

func (ts *aesTestSuite) TestAesDecodeFail() {
	enc := secure.NewAes()
	ts.IsTypef(&secure.AesEncoder{}, enc, "Is AesEncoder object")

	decoded, err := enc.SetKey(ts.keyOk).Decrypt(ts.textEncodedFail)
	ts.EqualErrorf(err, "ciphertext too short", "Is 'ciphertext too short' error")
	ts.Equalf("", decoded, "Not decoded")
}

func TestAes(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	suite.Run(t, new(aesTestSuite))
}
