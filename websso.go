package main

import (
	"fmt"
	"github.com/crewjam/saml"
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


	if r.URL.Path == Middleware.ServiceProvider.MetadataURL.Path {
		Middleware.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == Middleware.ServiceProvider.AcsURL.Path {
		ServeACS(Middleware, w,r)
		return
	}
	session, err := Middleware.Session.GetSession(r)
	if session != nil {
		logger.Info("Session found adding to request")
		r = r.WithContext(samlsp.ContextWithSession(r.Context(), session))
		return
	}
	if err == samlsp.ErrNoSession {
		HandleStartAuthFlow(Middleware,w, r)
		return
	}
}

// HandleStartAuthFlow is called to start the SAML authentication process.
func  HandleStartAuthFlow(m *samlsp.Middleware,w http.ResponseWriter, r *http.Request) {
	// If we try to redirect when the original request is the ACS URL we'll
	// end up in a loop. This is a programming error, so we panic here. In
	// general this means a 500 to the user, which is preferable to a
	// redirect loop.
	if r.URL.Path == m.ServiceProvider.AcsURL.Path {
		panic("don't wrap Middleware with RequireAccount")
	}

	var binding, bindingLocation string
	if m.Binding != "" {
		binding = m.Binding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
	} else {
		binding = saml.HTTPRedirectBinding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		if bindingLocation == "" {
			binding = saml.HTTPPostBinding
			bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		}
	}

	authReq, err := m.ServiceProvider.MakeAuthenticationRequest(bindingLocation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// relayState is limited to 80 bytes but also must be integrity protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a signed cookie that encodes the original URL which we'll check
	// against the SAML response when we get it.
	relayState, err := m.RequestTracker.TrackRequest(w, r, authReq.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println()

	if binding == saml.HTTPRedirectBinding {
		redirectURL := authReq.Redirect(relayState)
		w.Header().Add("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)
		return
	}
	if binding == saml.HTTPPostBinding {
		w.Header().Add("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		w.Header().Add("Content-type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><body>`))
		w.Write(authReq.Post(relayState))
		w.Write([]byte(`</body></html>`))
		return
	}
	panic("not reached")
}

func ServeACS(m *samlsp.Middleware,w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	possibleRequestIDs := []string{}
	possibleRequestIDs = append(possibleRequestIDs, "")


	trackedRequests := m.RequestTracker.GetTrackedRequests(r)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	assertion, err := m.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		m.OnError(w, r, err)
		return
	}

	m.CreateSessionFromAssertion(w, r, assertion)
	return
}


