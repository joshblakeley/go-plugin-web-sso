package main

import (
	"github.com/crewjam/saml/samlsp"
	"github.com/sirupsen/logrus"

	"net/http"
)

var (
	logger = logrus.New()
)


var Middleware *samlsp.Middleware


type SAMLConfig struct {
	IDPMetadataURL      string
	CertFile            string
	KeyFile             string
	ForceAuthentication bool
	SAMLBinding         string
	BaseURL string
}



// RequireAccount is HTTP middleware that requires that each request be
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middleware redirects the user
// to start the SAML auth flow.
//
func SAMLWebSSO(w http.ResponseWriter, r *http.Request){


	if r.URL.Path == Middleware.ServiceProvider.MetadataURL.Path || r.URL.Path == Middleware.ServiceProvider.AcsURL.Path {
		Middleware.ServeHTTP(w, r)
		return
	}

	session, err := Middleware.Session.GetSession(r)
	if session != nil {
		logger.Info("Session found adding to request")
		r = r.WithContext(samlsp.ContextWithSession(r.Context(), session))
		token, _ := r.Cookie("token")


		r.Header.Set("Authorization", "bearer "+ token.Value)
		return
	}
	if err == samlsp.ErrNoSession {
		Middleware.HandleStartAuthFlow(w, r)
		return
	}
}




