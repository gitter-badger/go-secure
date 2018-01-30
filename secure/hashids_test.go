package secure_test

import (
	"testing"

	"github.com/mailoman/go-secure/secure"
	"github.com/stretchr/testify/suite"
)

type hashidsTestSuite struct {
	suite.Suite

	text             string
	textEncoded      string
	textEncodedFail  string
	textEncodedShort string
	keyOk            string
	keyShort         string
}

func (ts *hashidsTestSuite) SetupSuite() {
	ts.text = "/myapi/test"
	ts.textEncoded = "R2bIzrfeXTPDUr7UJViP9I5VU2ECJwTe7"
	ts.textEncodedFail = "116A47bJD9jZIUQsiNrWyC.XXX-XZ"
	ts.textEncodedShort = "Nx1HyRtaqfwjCGWi86IdXH15UN8SrqsBg"
	ts.keyOk = "01234567891011121314151617181920"
	ts.keyShort = "123"
}

func (ts *hashidsTestSuite) TestHashidsEncodedOk() {
	enc := secure.NewHashids()
	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Is HashidsEncoder object")

	encoded, err := enc.SetKey(ts.keyOk).Encrypt(ts.text)

	ts.Nilf(err, "No errors")
	ts.Equalf(ts.textEncoded, encoded, "Encoded ok")
}

func (ts *hashidsTestSuite) TestHashidsEncodedShortOk() {
	enc := secure.NewHashids()
	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Is HashidsEncoder object")

	encoded, err := enc.SetKey(ts.keyShort).Encrypt(ts.text)

	ts.Nilf(err, "No errors")
	ts.Equalf(ts.textEncodedShort, encoded, "Encoded ok")
}

func (ts *hashidsTestSuite) TestHashidsDecodedOk() {
	enc := secure.NewHashids()
	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Is HashidsEncoder object")

	decoded, err := enc.SetKey(ts.keyOk).Decrypt(ts.textEncoded)

	ts.Nilf(err, "No errors")
	ts.Equalf(ts.text, decoded, "Decoded ok")
}

func (ts *hashidsTestSuite) TestHashidsEncodeFail() {
	enc := secure.NewHashids()
	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Is HashidsEncoder object")

	encoded, err := enc.SetKey(ts.keyOk).Encrypt("")
	ts.EqualErrorf(err, "encoding empty array of numbers makes no sense", "Is 'encoding empty array of numbers makes no sense' error")
	ts.Equalf("", encoded, "Not encoded")
}

func (ts *hashidsTestSuite) TestHashidsDecodeAlphabetFail() {
	enc := secure.NewHashids()
	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Is HashidsEncoder object")

	decoded, err := enc.SetKey(ts.keyOk).Decrypt(ts.textEncodedFail)
	ts.EqualErrorf(err, "alphabet used for hash was different", "Is 'alphabet used for hash was different' error")
	ts.Equalf("", decoded, "Not decoded")
}

func (ts *hashidsTestSuite) TestHashidsDecodeTextFail() {
	enc := secure.NewHashids()
	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Is HashidsEncoder object")

	decoded, err := enc.SetKey(ts.keyOk).Decrypt(ts.textEncoded + "extra string")
	ts.EqualErrorf(err, "alphabet used for hash was different", "Is 'alphabet used for hash was different' error")
	ts.NotEqualf(ts.text, decoded, "Not decoded")
}

func TestHashids(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	suite.Run(t, new(hashidsTestSuite))
}
