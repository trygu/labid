package token_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/statisticsnorway/labid/internal/token"
)

func SigningKey() jwk.Key {
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	privateKey, err := jwk.Import(newPrivateKey)
	if err != nil {
		panic(err)
	}
	jwk.AssignKeyID(privateKey)
	privateKey.Set("alg", "RS256")
	privateKey.Set("use", "sig")
	return privateKey
}

func JwkSet(keys ...jwk.Key) jwk.Set {
	s := jwk.NewSet()
	for _, k := range keys {
		if err := s.AddKey(k); err != nil {
			panic(err)
		}
	}
	return s
}

func JwksGetter(s jwk.Set) token.JwksGetter {
	return token.JwksGetterFunc(func(_ context.Context) (jwk.Set, error) {
		return s, nil
	})
}

func TestParseBrokenToken(t *testing.T) {
	key := SigningKey()
	pub, err := key.PublicKey()
	if err != nil {
		panic(err)
	}
	keySet := JwkSet(pub)
	broken := "abcdef"
	parser := token.NewKubernetesTokenParser(token.JwksGetterFunc(func(ctx context.Context) (jwk.Set, error) {
		return keySet, nil
	}))

	if kubeClaim, err := parser.Parse(context.Background(), broken); err == nil {
		t.Fatalf("unexpected success, kubeClaim=%v", *kubeClaim)
	}
}

func TestParseJwksFail(t *testing.T) {
	kubeClaim, err := token.NewKubernetesTokenParser(token.JwksGetterFunc(func(context.Context) (jwk.Set, error) {
		return nil, errors.New("fail")
	})).Parse(context.Background(), "")
	if err == nil {
		t.Fatalf("unexpected success, kubeClaim=%v", *kubeClaim)
	} else if !strings.HasPrefix(err.Error(), "get jwks:") {
		t.Fatalf("unexpected error, err=%s", err.Error())
	}
}

func TestParseInvalidKubernetesClaim(t *testing.T) {
	key := SigningKey()
	pub, err := key.PublicKey()
	if err != nil {
		panic(err)
	}
	keySet := JwkSet(pub)

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Claim("kubernetes.io", 5)
	jwtToken, err := tokenBuilder.Build()
	if err != nil {
		panic(err)
	}

	signed, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256(), key))

	parser := token.NewKubernetesTokenParser(JwksGetter(keySet))

	kubeClaim, err := parser.Parse(context.Background(), string(signed))

	if err == nil {
		t.Fatalf("unexpected success, kubeClaim=%v", *kubeClaim)
	} else if !strings.Contains(err.Error(), "parse and validate token:") {
		t.Fatalf("unexpected error, error=%s", err.Error())
	}
}

func TestParseValidToken(t *testing.T) {
	key := SigningKey()
	pub, err := key.PublicKey()
	if err != nil {
		panic(err)
	}
	keySet := JwkSet(pub)

	inClaim := token.KubernetesIoClaim{
		Namespace: "user-ssb-test",
		ServiceAccount: struct {
			Name string `json:"name"`
		}{
			"test",
		},
	}

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Claim("kubernetes.io", inClaim)
	jwtToken, err := tokenBuilder.Build()
	if err != nil {
		panic(err)
	}

	signed, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256(), key))

	parser := token.NewKubernetesTokenParser(JwksGetter(keySet))

	kubeClaim, err := parser.Parse(context.Background(), string(signed))

	if err != nil {
		t.Fatal(err)
	}

	switch {
	case kubeClaim.Namespace != inClaim.Namespace:
	case kubeClaim.ServiceAccount.Name != inClaim.ServiceAccount.Name:
	default:
		return
	}

	t.Fatalf("outcoming claim does not match ingoing, in=%v, out=%v", inClaim, *kubeClaim)
}
