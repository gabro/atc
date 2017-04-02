package auth

import (
	"crypto/rsa"
	"net/http"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/concourse/atc/auth/provider"
	"github.com/concourse/atc/dbng"
	"github.com/dgrijalva/jwt-go"
	"github.com/tedsuo/rata"
)

var SigningMethod = jwt.SigningMethodRS256

//go:generate counterfeiter . ProviderFactory

type ProviderFactory interface {
	GetProvider(dbng.Team, string) (provider.Provider, bool, error)
}

func NewOAuthHandler(
	logger lager.Logger,
	providerFactory ProviderFactory,
	teamFactory dbng.TeamFactory,
	signingKey *rsa.PrivateKey,
	expire time.Duration,
) (http.Handler, error) {
	return rata.NewRouter(
		OAuthRoutes,
		map[string]http.Handler{
			OAuthBegin: NewOAuthBeginHandler(
				logger.Session("oauth-begin"),
				providerFactory,
				signingKey,
				teamFactory,
				expire,
			),
			OAuthCallback: NewOAuthCallbackHandler(
				logger.Session("oauth-callback"),
				providerFactory,
				signingKey,
				teamFactory,
				expire,
			),
			LogOut: NewLogOutHandler(
				logger.Session("logout"),
			),
		},
	)
}
