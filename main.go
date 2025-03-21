package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	daplaGroupAnnotation = "dapla.ssb.no/impersonate-group"
	userNamespacePrefix  = "user-ssb-"
)

// Used for custom context keys
type ctxKey int

const (
	userInfoCtxKey ctxKey = iota
	tokenCtxKey
)

type config struct {
	IssuerUri string `env:"ISSUER_URI,required,notEmpty"`
	Port      string `env:"PORT" envDefault:"8080"`
}

type WellKnown struct {
	JwksUri string `json:"jwks_uri"`
}

type UserInfo struct {
	Name  string
	Group string
}

// FetchWellKnown assumes the well-know file is at {issuerUri}/.well-known/openid-configuration
// Is only used to get the JWKS URI, so will probably just k
func FetchWellKnown(issuerUri string) (WellKnown, error) {
	var wellKnown WellKnown
	wellKnownUri := fmt.Sprintf(
		"%s/.well-known/openid-configuration",
		strings.TrimSuffix(issuerUri, "/"),
	)

	wellKnownRes, err := http.Get(wellKnownUri)
	if err != nil {
		return wellKnown, err
	}
	if wellKnownRes.StatusCode != http.StatusOK {
		return wellKnown, fmt.Errorf("well known endpoint (%s) did not return 200 OK, got: %s", wellKnownUri, wellKnownRes.Status)
	}

	wellKnownDec := json.NewDecoder(wellKnownRes.Body)
	defer wellKnownRes.Body.Close()
	err = wellKnownDec.Decode(&wellKnown)
	return wellKnown, err
}

func GetJwks(key jwk.Key) http.HandlerFunc {
	jwks := jwk.NewSet()
	jwks.AddKey(key)
	return func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		enc.Encode(jwks)
	}
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

	wellKnown, err := FetchWellKnown(cfg.IssuerUri)
	if err != nil {
		panic(err)
	}

	// Establish a automatically updating cache of the external JWKS
	jwksCache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		panic(err)
	}
	getJwks := func(ctx context.Context) (jwk.Set, error) {
		return jwksCache.Lookup(ctx, wellKnown.JwksUri)
	}
	if err := jwksCache.Register(ctx, wellKnown.JwksUri); err != nil {
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

	// Create chi webserver
	r := chi.NewRouter()

	r.Use(middleware.Logger)

	// The token endpoints needs to
	// 1. Validate that there is a Bearer token, and that it
	//    is valid wrt. the external JWKS
	// 2. Figure out the user's context (username, access group)
	// 3. Create a JWT signed by our signing key, with our custom claims
	r.Route("/token", func(r chi.Router) {
		r.Use(JwkSetValidator(getJwks))
		r.Use(UserContext(clientset))
		r.Get("/", GetToken(privateKey))
	})

	r.Get("/jwks", GetJwks(publicKey))

	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), r); err != nil {
		panic(err)
	}
}

func GetToken(privateKey jwk.Key) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ui, ok := r.Context().Value(userInfoCtxKey).(UserInfo)
		if !ok {
			http.Error(w, "incorrect userinfo type", http.StatusInternalServerError)
			slog.Error("userinfo had type %T", r.Context().Value(userInfoCtxKey))
			return
		}

		jwtBuilder := jwt.NewBuilder()
		jwtBuilder.Subject(ui.Name)
		jwtBuilder.Claim("group", ui.Group)
		// Expiration time will be configurable via env vars
		jwtBuilder.Expiration(time.Now().Add(time.Hour))
		jwtBuilder.IssuedAt(time.Now())
		// Issuer will probably not be "labid" ...
		jwtBuilder.Issuer("labid")
		token, err := jwtBuilder.Build()
		if err != nil {
			http.Error(w, "error building jwt", http.StatusInternalServerError)
			slog.Error("build jwt", "error", err)
			return
		}

		signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privateKey))
		if err != nil {
			http.Error(w, "couldn't sign JWT", http.StatusInternalServerError)
			slog.Error("couldn't sign JWT", "error", err)
			return
		}

		resp := map[string]string{
			"token": string(signedToken),
		}
		enc := json.NewEncoder(w)
		if err := enc.Encode(resp); err != nil {
			http.Error(w, "error encoding token response", http.StatusInternalServerError)
		}
	}
}

func UserContext(k8sClient *kubernetes.Clientset) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := r.Context().Value(tokenCtxKey).(jwt.Token)
			if !ok {
				http.Error(w, "failed to retrieve token from context", http.StatusInternalServerError)
				return
			}

			var k8sMeta KubernetesIoClaim
			if err := token.Get("kubernetes.io", &k8sMeta); err != nil {
				http.Error(w, "incorrect token format", http.StatusInternalServerError)
				return
			}

			sa, err := k8sClient.CoreV1().ServiceAccounts(k8sMeta.Namespace).Get(r.Context(), k8sMeta.ServiceAccount.Name, v1.GetOptions{})
			if err != nil {
				http.Error(w, "could not find associated service account", http.StatusInternalServerError)
				return
			}

			group, ok := sa.Annotations[daplaGroupAnnotation]
			if !ok {
				http.Error(w, "service account is not associated with any group", http.StatusInternalServerError)
				return
			}

			name := strings.TrimPrefix(k8sMeta.Namespace, userNamespacePrefix)

			ui := UserInfo{
				Name:  name,
				Group: group,
			}

			ctx := context.WithValue(r.Context(), userInfoCtxKey, ui)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func JwkSetValidator(getJwks func(context.Context) (jwk.Set, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization", http.StatusUnauthorized)
				return
			}
			// Case insensitive check for "bearer "
			if !strings.EqualFold(authHeader[:7], "bearer ") {
				http.Error(w, "incorrect authorization type, only bearer supported", http.StatusForbidden)
				return
			}
			jwks, err := getJwks(r.Context())
			if err != nil {
				http.Error(w, "could not get JWKs", http.StatusInternalServerError)
				slog.Error("could not get JWKs", "error", err)
				return
			}
			// Strip away "bearer "
			tokenStr := authHeader[7:]
			token, err := jwt.Parse(
				[]byte(tokenStr),
				jwt.WithKeySet(jwks),
				jwt.WithValidate(true),
				// Type safe custom claims!
				jwt.WithTypedClaim("kubernetes.io", KubernetesIoClaim{}),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				slog.Error("error parsing token", "error", err)
				return
			}

			ctx := context.WithValue(r.Context(), tokenCtxKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type KubernetesIoClaim struct {
	Namespace      string `json:"namespace"`
	ServiceAccount struct {
		Name string `json:"name"`
	} `json:"serviceaccount"`
}
