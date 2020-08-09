package main

import (
	"github.com/crewjam/saml/samlsp"

	"github.com/TykTechnologies/tyk/log"
	"net/http"
)

var (
	logger = log.Get()
)

var Middleware *samlsp.Middleware

type SAMLConfig struct {
	IDPMetadataURL      string
	CertFile            string
	KeyFile             string
	ForceAuthentication bool
	SAMLBinding         string
	BaseURL             string
	SPMetadataURL       string
	SPAcsURL            string
	SPSloURL            string
	SessionJWTAud       string
	SessionJWTIss       string
	SessionJWTKeyFile   string
	SessionJWTMaxAge    int
}

// SAMLWebSSO is HTTP middleware that requires that each request be
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middleware redirects the user
// to start the SAML auth flow.
//
func SAMLWebSSO(w http.ResponseWriter, r *http.Request) {

	logger.Info(r.URL.Path)
	logger.Info(Middleware.ServiceProvider.AcsURL.Path)

	if r.URL.Path == Middleware.ServiceProvider.MetadataURL.Path {
		logger.Info("Serving metadata")
		Middleware.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == Middleware.ServiceProvider.AcsURL.Path {
		logger.Info("ACS called - checking assertion")
		Middleware.ServeHTTP(w, r)
		return
	}
	session, err := Middleware.Session.GetSession(r)
	if session != nil {
		logger.Info("Session found adding to request")
		r = r.WithContext(samlsp.ContextWithSession(r.Context(), session))
		token, _ := r.Cookie("token")

		r.Header.Set("Authorization", "bearer "+token.Value)
		return
	}
	if err == samlsp.ErrNoSession {
		logger.Info("No session found starting auth flow")
		Middleware.HandleStartAuthFlow(w, r)
		return
	}
}


