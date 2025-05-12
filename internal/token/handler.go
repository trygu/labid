package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	api "github.com/statisticsnorway/labid/api/oas"
)

var _ api.Handler = (*tokenHandler)(nil)

type tokenHandler struct {
	ParseToken           TokenParser
	TokenIssuer          TokenIssuer
	PopulateCurrentGroup CurrentGroupPopulator
	PopulateAllGroups    AllGroupsPopulator
}

type ThOptsFunc func(*tokenHandler) error

func WithCurrentGroupPopulator(p CurrentGroupPopulator) ThOptsFunc {
	return func(th *tokenHandler) error {
		th.PopulateCurrentGroup = p
		return nil
	}
}

func WithAllGroupsPopulator(p AllGroupsPopulator) ThOptsFunc {
	return func(th *tokenHandler) error {
		th.PopulateAllGroups = p
		return nil
	}
}

func NewTokenHandler(parser TokenParser, issuer TokenIssuer, opts ...ThOptsFunc) (*tokenHandler, error) {
	th := &tokenHandler{
		ParseToken:  parser,
		TokenIssuer: issuer,
	}

	for _, opt := range opts {
		if err := opt(th); err != nil {
			return nil, err
		}
	}

	return th, nil
}

type TokenParser func(ctx context.Context, rawToken string) (*KubernetesIoClaim, error)

type TokenIssuer interface {
	IssueToken(ctx context.Context, username string, audience []string, scopes []string, mappers ...Mapper) ([]byte, error)
	PublicKey() (jwk.Key, error)
}

type CurrentGroupPopulator func(ctx context.Context, serviceAccount, namespace string) Mapper

type AllGroupsPopulator func(ctx context.Context, username string) Mapper

func (h *tokenHandler) ExchangeToken(ctx context.Context, req *api.TokenExchangeRequest) (api.ExchangeTokenRes, error) {
	if req == nil {
		return &api.ExchangeToken4XXStatusCode{
			StatusCode: http.StatusBadRequest,
			Response: api.ExchangeToken4XX{
				Error: api.ExchangeToken4XXErrorInvalidRequest,
			},
		}, nil
	}

	var scopes []string
	if scopeString, ok := req.GetScope().Get(); ok {
		scopes = strings.Split(scopeString, ",")
	}

	kubernetesClaims, err := h.ParseToken(ctx, req.GetSubjectToken())
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			return &api.ExchangeToken4XXStatusCode{
				StatusCode: http.StatusBadRequest,
				Response: api.ExchangeToken4XX{
					Error:            api.ExchangeToken4XXErrorInvalidRequest,
					ErrorDescription: api.NewOptString(err.Error()),
				},
			}, nil
		}
		return nil, err
	}

	username := strings.TrimPrefix(kubernetesClaims.Namespace, UserNamespacePrefix)
	if username == kubernetesClaims.Namespace {
		return nil, fmt.Errorf("invalid user namespace %q", kubernetesClaims.Namespace)
	}

	var mappers []Mapper

	if h.PopulateCurrentGroup != nil && slices.Contains(scopes, "current_group") {
		mappers = append(mappers, h.PopulateCurrentGroup(ctx, kubernetesClaims.ServiceAccount.Name, kubernetesClaims.Namespace))
	}

	if h.PopulateAllGroups != nil && slices.Contains(scopes, "all_groups") {
		mappers = append(mappers, h.PopulateAllGroups(ctx, username))
	}

	issuedToken, err := h.TokenIssuer.IssueToken(ctx, username, req.Audience, scopes, mappers...)
	if err != nil {
		slog.Error(err.Error())
		return nil, errors.New("unexpected error issuing token")
	}

	return &api.ExchangeTokenOK{
		AccessToken:     string(issuedToken),
		IssuedTokenType: api.ExchangeTokenOKIssuedTokenTypeUrnIetfParamsOAuthGrantTypeJwt,
		TokenType:       api.ExchangeTokenOKTokenTypeBearer,
		ExpiresIn:       time.Hour.Seconds(),
	}, nil
}
