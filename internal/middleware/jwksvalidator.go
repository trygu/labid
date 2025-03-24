package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

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

			ctx := context.WithValue(r.Context(), TokenContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
