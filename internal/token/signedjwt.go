package token

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type signedJwtIssuer struct {
	SigningKey jwk.Key
	Issuer     string
	Expiry     time.Duration
}

type optFunc func(c *signedJwtIssuer)

type Mapper func(ctx context.Context, builder *jwt.Builder) error

func NewSignedJwtIssuer(issuer string, signingKey jwk.Key, opts ...optFunc) (*signedJwtIssuer, error) {
	sjc := &signedJwtIssuer{
		SigningKey: signingKey,
		Expiry:     time.Hour,
		Issuer:     issuer,
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

func (c *signedJwtIssuer) IssueToken(ctx context.Context, username string, audience []string, scopes []string, mappers ...Mapper) ([]byte, error) {
	jwtBuilder := jwt.NewBuilder()

	for _, m := range mappers {
		if err := m(ctx, jwtBuilder); err != nil {
			return nil, err
		}
	}

	jwtBuilder.Subject(username)

	jwtBuilder.Expiration(time.Now().Add(c.Expiry))
	jwtBuilder.IssuedAt(time.Now())

	if c.Issuer != "" {
		jwtBuilder.Issuer(c.Issuer)
	}

	jwtBuilder.Audience(audience)
	jwtBuilder.Claim("scope", strings.Join(scopes, ","))

	token, err := jwtBuilder.Build()
	if err != nil {
		return nil, err
	}

	return jwt.Sign(token, jwt.WithKey(jwa.RS256(), c.SigningKey))
}

func (c *signedJwtIssuer) PublicKey() (jwk.Key, error) {
	return c.SigningKey.PublicKey()
}
