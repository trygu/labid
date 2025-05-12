package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var (
	ErrInvalidToken = errors.New("invalid subject_token")
)

type KubernetesIoClaim struct {
	Namespace      string `json:"namespace"`
	ServiceAccount struct {
		Name string `json:"name"`
	} `json:"serviceaccount"`
}

type JwksGetter interface {
	Get(context.Context) (jwk.Set, error)
}

type JwksGetterFunc func(context.Context) (jwk.Set, error)

func (f JwksGetterFunc) Get(ctx context.Context) (jwk.Set, error) {
	return f(ctx)
}

type kubernetesTokenParser struct {
	Jwks JwksGetter
}

func NewKubernetesTokenParser(jwks JwksGetter) *kubernetesTokenParser {
	return &kubernetesTokenParser{
		Jwks: jwks,
	}
}

func (p *kubernetesTokenParser) Parse(ctx context.Context, rawToken string) (*KubernetesIoClaim, error) {
	jwks, err := p.Jwks.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("get jwks: %w", err)
	}

	token, err := jwt.Parse(
		[]byte(rawToken),
		jwt.WithKeySet(jwks),
		jwt.WithValidate(true),
		jwt.WithTypedClaim("kubernetes.io", KubernetesIoClaim{}),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: parse and validate token: %w", ErrInvalidToken, err)
	}

	var k8sMeta KubernetesIoClaim
	if err := token.Get("kubernetes.io", &k8sMeta); err != nil {
		return nil, fmt.Errorf("%w: unmarshal kubernetes.io claim: %w", ErrInvalidToken, err)
	}

	return &k8sMeta, nil
}
