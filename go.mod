module github.com/joshblakeley/websso-go

go 1.14

require (
	github.com/crewjam/saml v0.4.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/sirupsen/logrus v1.6.0
)

replace (
	github.com/pkg/errors => github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus => github.com/sirupsen/logrus v1.4.2
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200113162924-86b910548bc1

)
