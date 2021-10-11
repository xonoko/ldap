package ldap

import (
	"bytes"
	"github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	"math"
	"text/template"
)

func (conn *Connection) performLdapFilterGroupsSearch(userDN string, username string) ([]*ldap.Entry, error) {
	// Parse the filter template
	// Example "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"

	t, err := template.New("groupFilterTemplate").Parse(conn.client.config.GroupFilter)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create group filter template for LDAP search")
	}

	context := struct {
		UserDN   string
		Username string
	}{
		ldap.EscapeFilter(userDN),
		ldap.EscapeFilter(username),
	}

	var renderedQuery bytes.Buffer
	if err := t.Execute(&renderedQuery, context); err != nil {
		return nil, errors.Wrap(err, "cannot execute group filter template for LDAP search")
	}

	result, err := conn.conn.Search(&ldap.SearchRequest{
		BaseDN:       conn.client.config.GroupDN,
		Scope:        ldap.ScopeWholeSubtree,
		SizeLimit:    math.MaxInt32,
		Filter:       renderedQuery.String(),
		Attributes: []string{
			conn.client.config.GroupAttr,
		},
	})

	if err != nil {
		return nil, errors.Wrap(err, "cannot search LDAP")
	}

	return result.Entries, nil
}

func (conn *Connection) GetLdapGroups(username string) ([]string, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	err := conn.conn.Bind(conn.client.config.BindDN, conn.client.config.BindPassword)
	if err != nil {
		return nil, errors.Wrap(err, "LDAP bind failed")
	}

	userDN, err := conn.usernameToDN(username)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot find user in ldap: %s", username)
	}

	entries, err := conn.performLdapFilterGroupsSearch(userDN, username)
	//TODO use tokengroups

	if err != nil {
		return nil, err
	}

	groupMap := make(map[string]bool)

	for _, e := range entries {
		dn, err := ldap.ParseDN(e.DN)
		if err != nil || len(dn.RDNs) == 0 {
			continue
		}

		values := e.GetAttributeValues(conn.client.config.GroupAttr)
		if len(values) > 0 {
			for _, val := range values {
				groupCN := parseCN(val)
				groupMap[groupCN] = true
			}
		}
	}

	groups := make([]string, 0, len(groupMap))
	for key := range groupMap {
		groups = append(groups, key)
	}

	return groups, nil
}

