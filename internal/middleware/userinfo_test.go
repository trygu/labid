package middleware_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/statisticsnorway/labid/internal/middleware"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMissingToken(t *testing.T) {
	uc := middleware.UserContext(nil)(nil)
	req := &http.Request{}
	rec := httptest.NewRecorder()
	uc.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("UserContext middleware did not return 500 on missing token, got: %s", rec.Result().Status)
	}

	bodyRaw, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	if body := string(bodyRaw); !strings.Contains(body, "failed to retrieve token from context") {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestIncorectTokenType(t *testing.T) {
	uc := middleware.UserContext(nil)(nil)
	req := (&http.Request{}).WithContext(
		context.WithValue(
			context.Background(),
			middleware.TokenContextKey,
			"I'm just a string",
		),
	)
	rec := httptest.NewRecorder()
	uc.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("UserContext middleware did not return 500 on missing token, got: %s", rec.Result().Status)
	}

	bodyRaw, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	if body := string(bodyRaw); !strings.Contains(body, "failed to retrieve token from context") {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestIncorrectKuberneteIoClaim(t *testing.T) {
	token := jwt.New()
	token.Set("kubernetes.io", "I'm just a string")
	uc := middleware.UserContext(nil)(nil)
	req := (&http.Request{}).WithContext(
		context.WithValue(
			context.Background(),
			middleware.TokenContextKey,
			token,
		),
	)
	rec := httptest.NewRecorder()
	uc.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("UserContext middleware did not return 500 on missing token, got: %s", rec.Result().Status)
	}

	bodyRaw, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	if body := string(bodyRaw); !strings.Contains(body, "incorrect token format") {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestMissingServiceAccount(t *testing.T) {
	token := jwt.New()
	token.Set("kubernetes.io", middleware.KubernetesIoClaim{})
	uc := middleware.UserContext(func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error) {
		return nil, errors.New("missing SA")
	})(nil)
	req := (&http.Request{}).WithContext(
		context.WithValue(
			context.Background(),
			middleware.TokenContextKey,
			token,
		),
	)
	rec := httptest.NewRecorder()
	uc.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("UserContext middleware did not return 500 on missing token, got: %s", rec.Result().Status)
	}

	bodyRaw, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	if body := string(bodyRaw); !strings.Contains(body, "could not find associated service account") {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestNoDaplaGroupAnnotation(t *testing.T) {
	token := jwt.New()
	token.Set("kubernetes.io", middleware.KubernetesIoClaim{})
	uc := middleware.UserContext(func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error) {
		return &corev1.ServiceAccount{}, nil
	})(nil)
	req := (&http.Request{}).WithContext(
		context.WithValue(
			context.Background(),
			middleware.TokenContextKey,
			token,
		),
	)
	rec := httptest.NewRecorder()
	uc.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("UserContext middleware did not return 500 on missing token, got: %s", rec.Result().Status)
	}

	bodyRaw, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Errorf("Error parsing response: %v", err)
	}

	if body := string(bodyRaw); !strings.Contains(body, "service account is not associated with any group") {
		t.Errorf("unexpected response body: %s", body)
	}
}

func TestUserInfoContextSet(t *testing.T) {
	name := "dummy"
	group := "dummy-group"

	token := jwt.New()
	token.Set("kubernetes.io", middleware.KubernetesIoClaim{Namespace: fmt.Sprintf("%s%s", middleware.UserNamespacePrefix, name)})

	var responseContext context.Context
	contextRecorder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseContext = r.Context()
		w.Write([]byte{})
	})

	uc := middleware.UserContext(func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error) {
		return &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					middleware.DaplaGroupAnnotation: group,
				},
			},
		}, nil
	})(contextRecorder)
	req := (&http.Request{}).WithContext(
		context.WithValue(
			context.Background(),
			middleware.TokenContextKey,
			token,
		),
	)
	rec := httptest.NewRecorder()
	uc.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("UserContext middleware did not return 200 OK on missing token, got: %s", rec.Result().Status)
	}

	if responseContext == nil {
		t.Fatal("response context is nil")
	}

	ui, ok := responseContext.Value(middleware.UserInfoContextKey).(middleware.UserInfo)
	if !ok {
		t.Fatalf("incorrect type for UserInfo in context: %T", responseContext.Value(middleware.UserInfoContextKey))
	}

	if ui.Name != name {
		t.Errorf("UserInfo.Name = %s, expected %s", ui.Name, name)
	}

	if ui.Group != group {
		t.Errorf("UserInfo.Group = %s, expected %s", ui.Group, group)
	}
}
