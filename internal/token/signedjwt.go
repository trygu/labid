package token

import (
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type signedJwtCreator struct {
	SigningKey jwk.Key
	Issuer     string
	Expiry     time.Duration
}

type optFunc func(c *signedJwtCreator)

func NewSignedJwtCreator(signingKey jwk.Key, opts ...optFunc) (*signedJwtCreator, error) {
	sjc := &signedJwtCreator{
		SigningKey: signingKey,
		Expiry:     time.Hour,
		Issuer:     "labid",
	}
	for _, opt := range opts {
		opt(sjc)
	}
	if sjc.SigningKey == nil {
		return nil, errors.New("signing key cannot be nil")
	}
	if sjc.Expiry < 0 {
		return nil, errors.New("expiry cannot be negative")
	}
	return sjc, nil
}

func (c *signedJwtCreator) NewToken(username, group string) ([]byte, error) {
	jwtBuilder := jwt.NewBuilder()
	jwtBuilder.Subject(username)
	jwtBuilder.Claim("group", group)
	// Expiration time will be configurable via env vars
	jwtBuilder.Expiration(time.Now().Add(c.Expiry))
	jwtBuilder.IssuedAt(time.Now())

	// Issuer will probably not be "labid" ...
	if c.Issuer != "" {
		jwtBuilder.Issuer(c.Issuer)
	}

	token, err := jwtBuilder.Build()
	if err != nil {
		return nil, err
	}

	return jwt.Sign(token, jwt.WithKey(jwa.RS256(), c.SigningKey))
}
