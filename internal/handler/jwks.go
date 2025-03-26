package handler

import (
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func GetJwks(key jwk.Key) http.HandlerFunc {
	jwks := jwk.NewSet()
	jwks.AddKey(key)
	return func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		enc.Encode(jwks)
	}
}
