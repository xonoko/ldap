package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"math"
	"sync"
	"time"
)

type Client struct {
	ldap   LDAP
	urls   []string
	config Config
}

type Connection struct {
	conn   backendConnection
	client *Client
	mutex sync.Mutex
}

type Config struct {
	Urls []string

	Insecure bool
	CustomCA string
	StartTLS bool
	Timeout  time.Duration

	// BindDN is the DN of the user used to perform group search
	BindDN       string
	BindPassword string

	// UserDN is the DN under which user search is performed
	UserDN string
	// UserAttr is the name of the attribute to match for username on the user object
	UserAttr  string
	UPNDomain string

	// GroupDN is the DN under which group search is performed
	GroupDN     string
	GroupFilter string
	GroupAttr   string
}

func NewClient(config Config) (*Client, error) {
	if config.GroupFilter == "" {
		config.GroupFilter = "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"
	}
	if config.GroupDN == "" {
		return nil, errors.New("Cannot create LDAP client with empty GroupDN")
	}

	if config.UserAttr == "" {
		config.UserAttr = "cn"
	}
	if config.UserDN == "" {
		return nil, errors.New("Cannot create LDAP client with empty UserDN")
	}

	if config.BindDN == "" {
		return nil, errors.New("Cannot create LDAP client with empty BindDN")
	}
	if config.BindPassword == "" {
		return nil, errors.New("Cannot create LDAP client with empty BindPassword")
	}

	c := &Client{
		config: config,
		ldap:   &ldapImpl{},
	}
	return c, nil
}

func (c *Client) Connect() (*Connection, error) {
	var multiErr error
	for _, url := range c.config.Urls {
		conn, err := c.dialLDAP(url)
		if err != nil {
			multiErr =  multierror.Append(multiErr, err)
			continue
		}
		return &Connection{conn: conn, client: c}, nil
	}
	return nil, multiErr
}

func (conn *Connection) Close() {
	conn.conn.Close()
}

func (conn *Connection) CheckAuth(username, password string) error{
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	userDN, err := conn.usernameToDN(username)
	if err != nil {
		return errors.Wrapf(err, "cannot find user in ldap: %s", username)
	}
	if err := conn.conn.Bind(userDN, password); err != nil {
		return errors.Wrapf(err, "invalid credentials for binding user: %s", username)
	} else {
		return nil
	}
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: c.config.Insecure,
	}

	if c.config.CustomCA != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(c.config.CustomCA)) {
			return nil, errors.New("error adding custom CA, check format")
		}
		tlsConfig.RootCAs = caCertPool
	}
	return &tlsConfig, nil
}

func (c *Client) dialLDAP(ldapUrl string) (backendConnection, error) {
	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create tls config")
	}

	conn, err := c.ldap.DialURL(ldapUrl, c.ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, errors.Wrapf(err, "cannot dial ldap url: %s", ldapUrl)
	}

	if c.config.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			return nil, errors.Wrapf(err, "cannot start tls for ldap url: %s", ldapUrl)
		}
	}

	if c.config.Timeout > 0 {
		conn.SetTimeout(c.config.Timeout)
	}

	return conn, nil
}

func (conn *Connection) usernameToDN(username string) (string, error) {
	bindDN := ""

	err := conn.conn.Bind(conn.client.config.BindDN, conn.client.config.BindPassword)
	if err != nil {
		return bindDN, errors.Wrap(err, "LDAP bind failed")
	}
	var filter string

	if conn.client.config.UPNDomain != "" {
		filter = fmt.Sprintf("(userPrincipalName=%s@%s)", ldap.EscapeFilter(username), conn.client.config.UPNDomain)
	} else {
		filter = fmt.Sprintf("(%s=%s)", conn.client.config.UserAttr, ldap.EscapeFilter(username))
	}

	if conn.client.config.UPNDomain != "" {
		filter = fmt.Sprintf("(userPrincipalName=%s@%s)", ldap.EscapeFilter(username), conn.client.config.UPNDomain)
	}

	result, err := conn.conn.Search(&ldap.SearchRequest{
		BaseDN:    conn.client.config.UserDN,
		Scope:     ldap.ScopeWholeSubtree,
		Filter:    filter,
		SizeLimit: math.MaxInt32,
	})

	if err != nil {
		return bindDN, errors.Wrapf(err, "LDAP search for binddn failed")
	}
	if len(result.Entries) != 1 {
		return bindDN, errors.New("No or multiple results for binddn search")
	}
	bindDN = result.Entries[0].DN

	return bindDN, nil
}
