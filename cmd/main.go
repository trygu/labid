package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/caarlos0/env/v11"
	"github.com/go-chi/chi"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	api "github.com/statisticsnorway/labid/api/oas"
	"github.com/statisticsnorway/labid/internal/teamapi"
	"github.com/statisticsnorway/labid/internal/token"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type config struct {
	JwksUri        string `env:"JWKS_URI,required,notEmpty"`
	Port           string `env:"PORT" envDefault:"8080"`
	PrivateKeyFile string `env:"PRIVATE_KEY_FILE,required,notEmpty,unset"`

	TeamApiUrl          string `env:"TEAM_API_URL"`
	TeamApiClientId     string `env:"TEAM_API_CLIENT_ID"`
	TeamApiClientSecret string `env:"TEAM_API_CLIENT_SECRET"`
	TeamApiTokenUrl     string `env:"TEAM_API_TOKEN_URL"`

	Host string `env:"HOST,required,notEmpty"`
}

func main() {
	ctx := context.Background()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := env.ParseAsWithOptions[config](env.Options{
		Prefix: "LABID_",
	})
	if err != nil {
		errorAndExit(fmt.Errorf("parse environment variables: %w", err))
	}

	rawPem, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		errorAndExit(fmt.Errorf("read private signing key file: %w", err))
	}

	privateKey, publicKey, err := ParseRsaKeyPair(rawPem)
	if err != nil {
		errorAndExit(fmt.Errorf("parse RSA keypair: %w", err))
	}

	localJwks := jwk.NewSet()
	if err := localJwks.AddKey(publicKey); err != nil {
		errorAndExit(fmt.Errorf("add public key to local jwks: %w", err))
	}

	// Establish an automatically updating cache of the external JWKS
	jwksGetter, err := CachedJwksGetter(ctx, cfg.JwksUri)
	if err != nil {
		errorAndExit(fmt.Errorf("create cached jwks getter: %w", err))
	}

	clientset, err := initializeKubernetesClient()
	if err != nil {
		errorAndExit(fmt.Errorf("initialize kubernetes client: %w", err))
	}

	getSa := func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error) {
		return clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	}

	kubernetesTokenParser := token.NewKubernetesTokenParser(jwksGetter)

	signedJwtCreator, err := token.NewSignedJwtIssuer(
		cfg.Host,
		privateKey,
	)
	if err != nil {
		errorAndExit(fmt.Errorf("create signed jwt issuer: %w", err))
	}

	thOpts := []token.ThOptsFunc{
		token.WithCurrentGroupPopulator(token.CurrentGroupMapper(ctx, getSa)),
	}
	if cfg.TeamApiUrl != "" {
		thOpts = append(
			thOpts,
			token.WithAllGroupsPopulator(
				teamapi.NewClient(
					cfg.TeamApiUrl,
					cfg.TeamApiTokenUrl,
					cfg.TeamApiClientId,
					cfg.TeamApiClientSecret,
				).AllGroupsPopulator,
			),
		)
	}
	tokenHandler, err := token.NewTokenHandler(
		kubernetesTokenParser.Parse, signedJwtCreator,
		thOpts...,
	)
	if err != nil {
		errorAndExit(fmt.Errorf("create token handler: %w", err))
	}

	srv, err := api.NewServer(tokenHandler, api.WithMiddleware(token.Logging(log)))
	if err != nil {
		errorAndExit(fmt.Errorf("create api server: %w", err))
	}

	r := chi.NewRouter()
	r.Mount("/", srv)
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.Info("handle request", "method", r.Method, "pattern", r.Pattern)
				next.ServeHTTP(w, r)
			})
		})

		jwks, err := Jwks(localJwks)
		if err != nil {
			errorAndExit(fmt.Errorf("create jwks handler: %w", err))
		}
		r.Get("/jwks", jwks)
		r.Get("/.well-known/openid-configuration", WellKnown(cfg.Host))
	})

	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), r); err != nil {
		slog.Error(err.Error())
	}
}

func ParseRsaKeyPair(rawPrivateKey []byte) (private jwk.Key, public jwk.Key, err error) {
	p, _ := pem.Decode(rawPrivateKey)
	if p == nil {
		return nil, nil, errors.New("unable to decode private key")
	}

	rawPrivate, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	rawPrivate, ok := rawPrivate.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("unexpected private key type, must be RSA")
	}

	privateKey, err := jwk.Import(rawPrivate)
	if err != nil {
		return nil, nil, fmt.Errorf("import private key as jwk: %w", err)
	}
	jwk.AssignKeyID(privateKey)
	privateKey.Set("alg", "RS256")
	privateKey.Set("use", "sig")

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("get public key from private key: %w", err)
	}

	return privateKey, publicKey, nil
}

func CachedJwksGetter(ctx context.Context, jwksUri string) (token.JwksGetter, error) {
	jwksCache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("create jwks cache: %w", err)
	}
	if err := jwksCache.Register(ctx, jwksUri); err != nil {
		return nil, fmt.Errorf("register external jwks in cache: %w", err)
	}
	getJwks := func(ctx context.Context) (jwk.Set, error) {
		return jwksCache.Lookup(ctx, jwksUri)
	}
	if _, err := getJwks(ctx); err != nil {
		return nil, fmt.Errorf("validate jwks getter: %w", err)
	}
	return token.JwksGetterFunc(getJwks), nil
}

func errorAndExit(err error) {
	slog.Error(err.Error())
	os.Exit(1)
}

func initializeKubernetesClient() (*kubernetes.Clientset, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	return kubernetes.NewForConfig(config)
}

func WellKnown(host string) func(http.ResponseWriter, *http.Request) {
	wellknown := map[string]any{
		"issuer":           host,
		"jwks_uri":         fmt.Sprintf("%s/jwks", host),
		"token_endpoint":   fmt.Sprintf("%s/token", host),
		"scopes_supported": []string{"current_group", "all_groups"},
		"claims_supported": []string{"iss", "sub", "dapla.group", "dapla.groups"},
	}
	b, _ := json.Marshal(wellknown)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write(b)
	}
}

func Jwks(s jwk.Set) (func(http.ResponseWriter, *http.Request), error) {
	jwksBytes, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write(jwksBytes)
	}, nil
}
