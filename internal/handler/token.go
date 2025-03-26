package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/statisticsnorway/labid/internal/middleware"
)

type JwtCreator interface {
	NewToken(username, group string) ([]byte, error)
}

func GetToken(jwtCreator JwtCreator) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ui, ok := r.Context().Value(middleware.UserInfoContextKey).(middleware.UserInfo)
		if !ok {
			http.Error(w, "incorrect userinfo type", http.StatusInternalServerError)
			slog.Error("userinfo had type %T", r.Context().Value(middleware.UserInfoContextKey))
			return
		}

		token, err := jwtCreator.NewToken(ui.Name, ui.Group)
		if err != nil {
			http.Error(w, "error creating token", http.StatusInternalServerError)
			slog.Error("error creating token", "error", err)
			return
		}

		resp := map[string]string{
			"token": string(token),
		}
		enc := json.NewEncoder(w)
		if err := enc.Encode(resp); err != nil {
			http.Error(w, "error encoding token response", http.StatusInternalServerError)
		}
	}
}
