package db

import (
	"encoding/json"

	"github.com/concourse/atc"
)

type Team struct {
	Name  string
	Admin bool

	BasicAuth    *atc.BasicAuth `json:"basic_auth"`
	Auth         map[string]*json.RawMessage
	GitHubAuth   *GitHubAuth   `json:"github_auth"`
	UAAAuth      *UAAAuth      `json:"uaa_auth"`
	GenericOAuth *GenericOAuth `json:"genericoauth_auth"`
}

type SavedTeam struct {
	ID int
	Team
}

type GitHubAuth struct {
	ClientID      string       `json:"client_id"`
	ClientSecret  string       `json:"client_secret"`
	Organizations []string     `json:"organizations"`
	Teams         []GitHubTeam `json:"teams"`
	Users         []string     `json:"users"`
	AuthURL       string       `json:"auth_url"`
	TokenURL      string       `json:"token_url"`
	APIURL        string       `json:"api_url"`
}

type UAAAuth struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	CFSpaces     []string `json:"cf_spaces"`
	CFURL        string   `json:"cf_url"`
	CFCACert     string   `json:"cf_ca_cert"`
}

type GenericOAuth struct {
	AuthURL       string            `json:"auth_url"`
	AuthURLParams map[string]string `json:"auth_url_params"`
	TokenURL      string            `json:"token_url"`
	ClientID      string            `json:"client_id"`
	ClientSecret  string            `json:"client_secret"`
	DisplayName   string            `json:"display_name"`
	Scope         string            `json:"scope"`
}

type GitHubTeam struct {
	OrganizationName string `json:"organization_name"`
	TeamName         string `json:"team_name"`
}
