package ldap

import (
	"crypto/tls"
	"github.com/go-ldap/ldap/v3"
	"time"
)

type LDAP interface {
	DialURL(url string, opts ...ldap.DialOpt) (backendConnection, error)
	DialWithTLSConfig(tc *tls.Config) ldap.DialOpt
}

type ldapImpl struct{}

func (l *ldapImpl) DialURL(url string, opts ...ldap.DialOpt) (backendConnection, error) {
	return ldap.DialURL(url, opts...)
}

func (l *ldapImpl) DialWithTLSConfig(tc *tls.Config) ldap.DialOpt {
	return ldap.DialWithTLSConfig(tc)
}

type backendConnection interface {
	Bind(username, password string) error
	Close()
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	StartTLS(config *tls.Config) error
	SetTimeout(timeout time.Duration)
	UnauthenticatedBind(username string) error
}


