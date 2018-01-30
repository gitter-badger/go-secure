package secure_test

import (
	"testing"

	"github.com/mailoman/go-secure/secure"
	"github.com/stretchr/testify/suite"
)

type secureTestSuite struct {
	suite.Suite
}

func (ts *secureTestSuite) TestEncryptFactoryAesOk() {
	enc, err := secure.EncryptFactory(secure.MethodAES)

	ts.Nilf(err, "No errors")
	ts.IsTypef(&secure.AesEncoder{}, enc, "Factory provides AesEncoder object")

	ts.Truef(enc.Isa(secure.MethodAES), "Check encoder type by name")
}

func (ts *secureTestSuite) TestEncryptFactoryHashidsOk() {
	enc, err := secure.EncryptFactory(secure.MethodHashids)

	ts.Nilf(err, "No errors")
	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Factory provides HashidsEncoder object")

	ts.Truef(enc.Isa(secure.MethodHashids), "Check encoder type by name")
}

func (ts *secureTestSuite) TestNewAesOk() {
	enc := secure.NewAes()

	ts.IsTypef(&secure.AesEncoder{}, enc, "Factory provides AesEncoder object")

	ts.Truef(enc.Isa(secure.MethodAES), "Check encoder type by name")
}

func (ts *secureTestSuite) TestNewHashidsOk() {
	enc := secure.NewHashids()

	ts.IsTypef(&secure.HashidsEncoder{}, enc, "Factory provides HashidsEncoder object")

	ts.Truef(enc.Isa(secure.MethodHashids), "Check encoder type by name")
}

func (ts *secureTestSuite) TestEncryptFactoryFail() {
	enc, err := secure.EncryptFactory("unknown method")

	ts.EqualErrorf(err, "not supported","Is 'not supported' error")
	ts.Nilf(enc, "Factory provides nil for unknown methods/types")
}

func TestSecure(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	suite.Run(t, new(secureTestSuite))
}
