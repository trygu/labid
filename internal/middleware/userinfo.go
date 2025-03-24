package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
	corev1 "k8s.io/api/core/v1"
)

type UserInfo struct {
	Name  string
	Group string
}

type KubernetesIoClaim struct {
	Namespace      string `json:"namespace"`
	ServiceAccount struct {
		Name string `json:"name"`
	} `json:"serviceaccount"`
}

type ServiceAccountGetter func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error)

func UserContext(getServiceAccount ServiceAccountGetter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := r.Context().Value(TokenContextKey).(jwt.Token)
			if !ok {
				http.Error(w, "failed to retrieve token from context", http.StatusInternalServerError)
				return
			}

			var k8sMeta KubernetesIoClaim
			if err := token.Get("kubernetes.io", &k8sMeta); err != nil {
				http.Error(w, "incorrect token format", http.StatusInternalServerError)
				return
			}

			sa, err := getServiceAccount(r.Context(), k8sMeta.ServiceAccount.Name, k8sMeta.Namespace)
			if err != nil {
				http.Error(w, "could not find associated service account", http.StatusInternalServerError)
				return
			}

			group, ok := sa.Annotations[DaplaGroupAnnotation]
			if !ok {
				http.Error(w, "service account is not associated with any group", http.StatusInternalServerError)
				return
			}

			name := strings.TrimPrefix(k8sMeta.Namespace, UserNamespacePrefix)

			ui := UserInfo{
				Name:  name,
				Group: group,
			}

			ctx := context.WithValue(r.Context(), UserInfoContextKey, ui)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
