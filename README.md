# go-plugin-web-sso
Go plugin for Web SSO SAML with Tyk API Gateway

Proof of Concept - contributions welcome

For how to get started with Go plugins and Tyk see here:
https://tyk.io/docs/plugins/supported-languages/golang/

# What it does

Logs a user in via specified IDP using SAML Post or redirect binding.
Retrieves their SAML assertion and maps all attributes in it to a signed JWT as a browser cookie.
Cookie is then used to fill Authorization header for authn authz etc in Tyk.


# How to use

First lets configure what we want via ENV vars on the Gateway Server or container. There are two sides to the configuration of this plugin. 
Firstly, we need to set up our relationship with our IDP so we can complete the SAML login flow. 
Next, we should configure the nature of the JWT we create to represent the logged in session of the user who is accessing the services. The signing key aud, iss etc are all configurable to you can create a token that is acceptable to your backend service.




