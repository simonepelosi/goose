package identity

import (
	gc "gopkg.in/check.v1"

	"github.com/go-goose/goose/v5/testing/httpsuite"
	"github.com/go-goose/goose/v5/testservices/identityservice"
)

type V3AppCredTestSuite struct {
	httpsuite.HTTPSuite
}

var _ = gc.Suite(&V3AppCredTestSuite{})

func (s *V3AppCredTestSuite) TestAuthAgainstServer(c *gc.C) {
	service := identityservice.NewV3AppCred()
	service.SetupHTTP(s.Mux)
	credInfo := service.AddCredential(
		"cred-id", "cred-secret", "token-value",
		"user-id", "project-id", "project-name",
	)
	var l Authenticator = &V3AppCred{}
	creds := Credentials{
		URL:                         s.Server.URL + "/v3/auth/tokens",
		ApplicationCredentialID:     "cred-id",
		ApplicationCredentialSecret: "cred-secret",
	}
	auth, err := l.Auth(&creds)
	c.Assert(err, gc.IsNil)
	c.Assert(auth.Token, gc.Equals, credInfo.Token)
	c.Assert(auth.TenantId, gc.Equals, credInfo.ProjectId)
	c.Assert(auth.TenantName, gc.Equals, credInfo.ProjectName)
	c.Assert(auth.UserId, gc.Equals, credInfo.UserId)
}

func (s *V3AppCredTestSuite) TestAuthWrongSecret(c *gc.C) {
	service := identityservice.NewV3AppCred()
	service.SetupHTTP(s.Mux)
	service.AddCredential(
		"cred-id", "cred-secret", "token-value",
		"user-id", "project-id", "project-name",
	)
	var l Authenticator = &V3AppCred{}
	creds := Credentials{
		URL:                         s.Server.URL + "/v3/auth/tokens",
		ApplicationCredentialID:     "cred-id",
		ApplicationCredentialSecret: "wrong-secret",
	}
	_, err := l.Auth(&creds)
	c.Assert(err, gc.NotNil)
}

func (s *V3AppCredTestSuite) TestAuthMissingID(c *gc.C) {
	var l Authenticator = &V3AppCred{}
	creds := Credentials{
		URL:                         "http://example.invalid/v3/auth/tokens",
		ApplicationCredentialSecret: "cred-secret",
	}
	_, err := l.Auth(&creds)
	c.Assert(err, gc.ErrorMatches, "application credential id not specified")
}

func (s *V3AppCredTestSuite) TestAuthMissingSecret(c *gc.C) {
	var l Authenticator = &V3AppCred{}
	creds := Credentials{
		URL:                     "http://example.invalid/v3/auth/tokens",
		ApplicationCredentialID: "cred-id",
	}
	_, err := l.Auth(&creds)
	c.Assert(
		err, gc.ErrorMatches, "application credential secret not specified",
	)
}

// Even if a caller mistakenly sets TenantName/Domain on the
// Credentials (fields meant for password auth), V3AppCred must never
// put a scope on the wire: Keystone rejects a scoped request for an
// already project-scoped application credential.
func (s *V3AppCredTestSuite) TestAuthNeverSendsScope(c *gc.C) {
	service := identityservice.NewV3AppCred()
	service.SetupHTTP(s.Mux)
	credInfo := service.AddCredential(
		"cred-id", "cred-secret", "token-value",
		"user-id", "project-id", "project-name",
	)
	var l Authenticator = &V3AppCred{}
	creds := Credentials{
		URL:                         s.Server.URL + "/v3/auth/tokens",
		ApplicationCredentialID:     "cred-id",
		ApplicationCredentialSecret: "cred-secret",
		TenantName:                  "some-other-project",
		Domain:                      "some-domain",
	}
	auth, err := l.Auth(&creds)
	c.Assert(err, gc.IsNil)
	c.Assert(auth.Token, gc.Equals, credInfo.Token)
}
