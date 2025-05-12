package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
		panic(err)
	}

	rawPem, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		panic(err)
	}

	p, _ := pem.Decode(rawPem)
	if p == nil {
		panic("no private key found")
	}

	rawPrivate, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}

	rawPrivate, ok := rawPrivate.(*rsa.PrivateKey)
	if !ok {
		panic("unexpected key type")
	}

	privateKey, err := jwk.Import(rawPrivate)
	if err != nil {
		panic(err)
	}
	jwk.AssignKeyID(privateKey)
	privateKey.Set("alg", "RS256")
	privateKey.Set("use", "sig")

	pubKey, err := privateKey.PublicKey()
	if err != nil {
		errorAndExit(err)
	}

	localJwks := jwk.NewSet()
	if err := localJwks.AddKey(pubKey); err != nil {
		errorAndExit(err)
	}

	// Establish an automatically updating cache of the external JWKS
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

	clientset, err := initializeKubernetesClient()
	if err != nil {
		errorAndExit(err)
	}

	getSa := func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error) {
		return clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	}

	kubernetesTokenParser := token.NewKubernetesTokenParser(token.JwksGetterFunc(getJwks))

	signedJwtCreator, err := token.NewSignedJwtIssuer(
		cfg.Host,
		privateKey,
	)
	if err != nil {
		panic(err.Error())
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
		errorAndExit(err)
	}

	srv, err := api.NewServer(tokenHandler, api.WithMiddleware(token.Logging(log)))
	if err != nil {
		errorAndExit(err)
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
		r.Get("/jwks", func(w http.ResponseWriter, r *http.Request) {
			enc := json.NewEncoder(w)
			if err := enc.Encode(localJwks); err != nil {
				log.Error("error writing jwks", "error", err)
			}
		})
		r.Get("/.well-known/openid-configuration", WellKnown(cfg.Host))
	})

	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), r); err != nil {
		slog.Error(err.Error())
	}
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
