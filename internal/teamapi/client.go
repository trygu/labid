package teamapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/statisticsnorway/labid/internal/token"
	"golang.org/x/oauth2/clientcredentials"
)

type client struct {
	httpClient *http.Client
	teamApiUrl string
}

type optFunc func(*client)

func NewClient(teamApiUrl, tokenUrl, clientId, clientSecret string, opts ...optFunc) *client {
	httpClient := (&clientcredentials.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		TokenURL:     tokenUrl,
	}).Client(context.Background())
	httpClient.Timeout = time.Second * 10

	c := &client{
		httpClient: httpClient,
		teamApiUrl: teamApiUrl,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type EmbeddedResponse[T any] struct {
	Embedded T `json:"_embedded"`
}

type Group struct {
	UniformName string `json:"uniform_name"`
}

type GroupsResponse struct {
	Groups []Group `json:"groups"`
}

func (c *client) ListGroups(userPrincipalEmail string) ([]string, error) {
	endpoint := fmt.Sprintf("%s/users/%s/groups", c.teamApiUrl, userPrincipalEmail)

	res, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("get user groups for %q: %w", userPrincipalEmail, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		var groups EmbeddedResponse[GroupsResponse]
		dec := json.NewDecoder(res.Body)
		if err := dec.Decode(&groups); err != nil {
			return nil, fmt.Errorf("decode userinfo response: %w", err)
		}
		var flatGroups []string
		for _, g := range groups.Embedded.Groups {
			flatGroups = append(flatGroups, g.UniformName)
		}
		return flatGroups, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("team api could not find user %q", userPrincipalEmail)
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError:
		return nil, fmt.Errorf("get user groups for %q, team api returned %q", userPrincipalEmail, res.Status)
	default:
		return nil, fmt.Errorf("get user groups for %q, team api returned unknown status %q", userPrincipalEmail, res.Status)
	}
}

func (c *client) AllGroupsPopulator(ctx context.Context, username string) token.Mapper {
	return func(ctx context.Context, builder *jwt.Builder) error {
		groups, err := c.ListGroups(fmt.Sprintf("%s@ssb.no", username))
		if err != nil {
			return err
		}

		builder.Claim("dapla.groups", groups)
		return nil
	}
}
