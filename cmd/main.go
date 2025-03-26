package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/caarlos0/env/v11"
	"github.com/go-chi/chi/v5"
	chimiddle "github.com/go-chi/chi/v5/middleware"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/statisticsnorway/labid/internal/handler"
	"github.com/statisticsnorway/labid/internal/middleware"
	"github.com/statisticsnorway/labid/internal/token"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type config struct {
	JwksUri string `env:"JWKS_URI,required,notEmpty"`
	Port    string `env:"PORT" envDefault:"8080"`
}

type WellKnown struct {
	JwksUri string `json:"jwks_uri"`
}

func main() {
	ctx := context.Background()

	// Generate a signing key
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

	// Get corresponding public key, which will be exposed via /jwks
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		panic(err)
	}

	cfg, err := env.ParseAsWithOptions[config](env.Options{
		Prefix: "LABID_",
	})
	if err != nil {
		panic(err)
	}

	// Establish a automatically updating cache of the external JWKS
	jwksCache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		panic(err)
	}
	getJwks := func(ctx context.Context) (jwk.Set, error) {
		return jwksCache.Lookup(ctx, cfg.JwksUri)
	}
	if err := jwksCache.Register(ctx, cfg.JwksUri); err != nil {
		panic(err)
	}

	// Create Kubernetes client
	// NOTE: this only works for in-cluster workloads. If running locally you need to
	// replace this section with sometihng else. In the future this will be easily
	// configurable.
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	getServiceAccount := func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error) {
		return clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	}

	signedJwtCreator, err := token.NewSignedJwtCreator(privateKey)
	if err != nil {
		panic(err.Error())
	}

	// Create chi webserver
	r := chi.NewRouter()

	r.Use(chimiddle.Logger)

	// The token endpoints needs to
	// 1. Validate that there is a Bearer token, and that it
	//    is valid wrt. the external JWKS
	// 2. Figure out the user's context (username, access group)
	// 3. Create a JWT signed by our signing key, with our custom claims
	r.Route("/token", func(r chi.Router) {
		r.Use(middleware.JwkSetValidator(getJwks))
		r.Use(middleware.UserContext(getServiceAccount))
		r.Get("/", handler.GetToken(signedJwtCreator))
	})

	r.Get("/jwks", handler.GetJwks(publicKey))

	err = http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), r)
	slog.Info(err.Error())
}
