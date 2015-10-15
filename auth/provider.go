package auth

import (
	"net/http"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type Providers map[string]Provider

//go:generate counterfeiter . Provider

type Provider interface {
	OAuthClient
	Verifier
}

type OAuthClient interface {
	AuthCodeURL(string, ...oauth2.AuthCodeOption) string
	Exchange(context.Context, string) (*oauth2.Token, error)
	Client(context.Context, *oauth2.Token) *http.Client
}

type Verifier interface {
	Verify(*http.Client) (bool, error)
}