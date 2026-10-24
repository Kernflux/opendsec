package images

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Credentials log in to a registry: a user name and password (or an access
// token used as the password, as GitLab, Harbor robot accounts and GHCR
// take), or an identity token (an OAuth2 refresh token, which `docker login`
// stores for some registries, e.g. Azure's).
type Credentials struct {
	Username, Password string
	IdentityToken      string
}

func (c *Credentials) empty() bool {
	return c == nil || c.Username == "" && c.Password == "" && c.IdentityToken == ""
}

// RegistryAuth is the credentials of a docker config file, by registry
// host (as ParseReference names it).
type RegistryAuth struct {
	Path  string
	creds map[string]Credentials
	// Registries whose credentials are kept by a credential helper
	// ("credsStore", "credHelpers"), which is not run.
	helpers map[string]string
}

// DefaultAuthFile is where `docker login` keeps credentials:
// $REGISTRY_AUTH_FILE (podman's variable; same format), else
// $DOCKER_CONFIG/config.json, else ~/.docker/config.json.
func DefaultAuthFile() string {
	if f := os.Getenv("REGISTRY_AUTH_FILE"); f != "" {
		return f
	}
	if d := os.Getenv("DOCKER_CONFIG"); d != "" {
		return filepath.Join(d, "config.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".docker", "config.json")
}

// LoadAuthFile reads a docker config file's "auths" (and notes its
// credential helpers). A missing file is no credentials, not an error.
func LoadAuthFile(path string) (*RegistryAuth, error) {
	ra := &RegistryAuth{Path: path, creds: map[string]Credentials{}, helpers: map[string]string{}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ra, nil
	}
	if err != nil {
		return nil, err
	}
	var f struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			Username      string `json:"username"`
			Password      string `json:"password"`
			IdentityToken string `json:"identitytoken"`
		} `json:"auths"`
		CredsStore  string            `json:"credsStore"`
		CredHelpers map[string]string `json:"credHelpers"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for key, a := range f.Auths {
		c := Credentials{Username: a.Username, Password: a.Password, IdentityToken: a.IdentityToken}
		if a.Auth != "" {
			raw, err := base64.StdEncoding.DecodeString(a.Auth)
			if err != nil {
				return nil, fmt.Errorf("%s: auths.%s: bad auth field", path, key)
			}
			c.Username, c.Password, _ = strings.Cut(string(raw), ":")
		}
		if !c.empty() {
			ra.creds[registryHost(key)] = c
		} else if f.CredsStore != "" {
			ra.helpers[registryHost(key)] = f.CredsStore // docker login with a store leaves an empty entry
		}
	}
	for key, h := range f.CredHelpers {
		ra.helpers[registryHost(key)] = h
	}
	return ra, nil
}

// For returns the credentials for registry (a ParseReference registry).
// It fails when they exist but are kept by a credential helper.
func (ra *RegistryAuth) For(registry string) (*Credentials, error) {
	if ra == nil {
		return nil, nil
	}
	if c, ok := ra.creds[registry]; ok {
		return &c, nil
	}
	if h, ok := ra.helpers[registry]; ok {
		return nil, fmt.Errorf("%s keeps the credentials for %s in the credential helper docker-credential-%s, which is not run: "+
			"pass -username and -password-stdin instead", ra.Path, registry, h)
	}
	return nil, nil
}

// registryHost maps a docker config key ("https://index.docker.io/v1/",
// "harbor.example.com", "https://ghcr.io") to ParseReference's registry.
func registryHost(key string) string {
	h := key
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	h, _, _ = strings.Cut(h, "/")
	switch h {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return "registry-1.docker.io"
	}
	return h
}
