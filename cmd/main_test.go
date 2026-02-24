package main

import (
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestWellKnown(t *testing.T) {

	wk := WellKnown("testing")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	wk(w, req)
	res := w.Result()

	if contentType := res.Header.Get("Content-Type"); contentType != "application/json" {
		t.Errorf("expected content-type application/json, got %q", contentType)
	}
}

func TestJwks(t *testing.T) {
	wk, _ := Jwks(jwk.NewSet())

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	wk(w, req)
	res := w.Result()

	if contentType := res.Header.Get("Content-Type"); contentType != "application/json" {
		t.Errorf("expected content-type application/json, got %q", contentType)
	}
}
