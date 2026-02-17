package daplaapi

import (
	"context"
	"fmt"
	"time"

	"github.com/hasura/go-graphql-client"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/statisticsnorway/labid/internal/token"
	"golang.org/x/oauth2"
)

type Client struct {
	graphqlClient *graphql.Client
	apiUrl        string
}

type optFunc func(*Client)

func NewClient(apiUrl, serviceAccountToken string, opts ...optFunc) *Client {
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: serviceAccountToken})
	httpClient := oauth2.NewClient(context.Background(), src)
	httpClient.Timeout = time.Second * 10

	grahqlClient := graphql.NewClient(apiUrl, httpClient)

	c := &Client{
		graphqlClient: grahqlClient,
		apiUrl:        apiUrl,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) ListGroups(ctx context.Context, userPrincipalEmail string) ([]string, error) {
	var userGroupsQuery struct {
		User struct {
			Groups struct {
				Nodes []struct {
					Group struct {
						Name graphql.String
					}
				}
			} `graphql:"groups(first: 1000)"`
		} `graphql:"user(email: $email)"`
	}
	variables := map[string]interface{}{
		"email": graphql.String(userPrincipalEmail),
	}

	err := c.graphqlClient.Query(ctx, &userGroupsQuery, variables)
	if err != nil {
		return nil, fmt.Errorf("query for dapla api failed %w", err)
	}
	var groups []string
	for _, node := range userGroupsQuery.User.Groups.Nodes {
		groups = append(groups, string(node.Group.Name))
	}
	return groups, nil
}

func (c *Client) AllGroupsPopulator(ctx context.Context, username string) token.Mapper {
	return func(ctx context.Context, builder *jwt.Builder) error {
		groups, err := c.ListGroups(ctx, fmt.Sprintf("%s@ssb.no", username))
		if err != nil {
			return err
		}

		builder.Claim("dapla.groups", groups)
		return nil
	}
}
