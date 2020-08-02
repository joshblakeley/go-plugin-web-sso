package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"net/http"
	"net/url"
)

func init() {
	config := &SAMLConfig{
		IDPMetadataURL: "https://login.microsoftonline.com/2a3490ef-c3df-4323-ae94-a75f83817991/federationmetadata/2007-06/federationmetadata.xml?appid=336fcc57-ddf4-4748-ab81-69dadbaf2648",                  //os.Getenv("TYK_SAML_METADATA_URL"),
		CertFile: "myservice.cert",
		KeyFile: "myservice.key",
		BaseURL: "https://8e1c71502ab8.ngrok.io",    //os.Getenv("TYK_SAML_BASE_URL"),
		ForceAuthentication:true,
	}


	logger.Debug("Initialising middleware SAML")
	//needs to match the signing cert if IDP
	keyPair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		logger.Errorf("Error loading keypair: %v", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		logger.Errorf("Error parsing certificate: %v", err)
	}

	idpMetadataURL, err := url.Parse(config.IDPMetadataURL)
	if err != nil {
		logger.Errorf("Error parsing IDP metadata URL: %v", err)
	}
	logger.Debugf("IDPmetadataURL is: %v", idpMetadataURL.String())

	rootURL, err := url.Parse(config.BaseURL)
	if err != nil {
		logger.Errorf("Error parsing SAMLBaseURL: %v", err)
	}

	httpClient := http.DefaultClient

	metadata, err := samlsp.FetchMetadata(context.TODO(), httpClient, *idpMetadataURL)
	if err != nil {
		logger.Errorf("Error retrieving IDP Metadata: %v", err)
	}

	logger.Debugf("Root URL: %v", rootURL.String())

	opts := samlsp.Options{
		URL: *rootURL,
		Key: keyPair.PrivateKey.(*rsa.PrivateKey),
	}

	metadataURL := rootURL.ResolveReference(&url.URL{Path: "websso/saml/metadata"})
	acsURL := rootURL.ResolveReference(&url.URL{Path: "websso/saml/acs"})
	sloURL := rootURL.ResolveReference(&url.URL{Path: "websso/saml/slo"})

	logger.Debugf("SP metadata URL: %v", metadataURL.String())
	logger.Debugf("SP acs URL: %v", acsURL.String())

	var forceAuthn = config.ForceAuthentication


	Middleware = &samlsp.Middleware{
		ServiceProvider: saml.ServiceProvider{
			EntityID:          metadataURL.String(),
			Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       keyPair.Leaf,
			MetadataURL:       *metadataURL,
			AcsURL:            *acsURL,
			SloURL:            *sloURL,
			IDPMetadata:       metadata,
			ForceAuthn:        &forceAuthn,
		},
		//Binding:         saml.HTTPPostBinding,
		OnError:         samlsp.DefaultOnError,
		Session:         samlsp.DefaultSessionProvider(opts),
	}

	Middleware.RequestTracker = samlsp.DefaultRequestTracker(opts, &Middleware.ServiceProvider)

	logger.Info("SAML Middleware initialised")
}


func main(){
	//not run for a Go plugin
}