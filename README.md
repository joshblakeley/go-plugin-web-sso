# go-plugin-web-sso
Go plugin for Web SSO SAML with Tyk API Gateway

Proof of Concept - contributions welcome

# What it does

Logs a user in via specified IDP using SAML Post or redirect binding.
Retrieves their SAML assertion and maps all attributes in it to a signed JWT as a browser cookie.
Cookie is then used to fill Authorization header for authn authz etc in Tyk.


# How to use

Plugin:
1. Upload the signing keycert for your SAML requests. 
2. Configure IDP metadata URL
3. Choose binding type (Default is redirect.)
4. Specify your metadata and ACS urls


Tyk:
Load plugin to an API in Tyk 

Make a request to any resource to trigger initial flow.


