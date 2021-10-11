package ldap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	"strings"
)

func sidToString(b []byte) (string, error) {
	reader := bytes.NewReader(b)

	var revision, subAuthorityCount uint8
	var identifierAuthorityParts [3]uint16

	if err := binary.Read(reader, binary.LittleEndian, &revision); err != nil {
		return "", errors.Wrapf(err, "SID %#v convert failed reading Revision", b)
	}

	if err := binary.Read(reader, binary.LittleEndian, &subAuthorityCount); err != nil {
		return "", errors.Wrapf(err, "SID %#v convert failed reading SubAuthorityCount", b)
	}

	if err := binary.Read(reader, binary.BigEndian, &identifierAuthorityParts); err != nil {
		return "", errors.Wrapf(err, "SID %#v convert failed reading IdentifierAuthority", b)
	}
	identifierAuthority := (uint64(identifierAuthorityParts[0]) << 32) + (uint64(identifierAuthorityParts[1]) << 16) + uint64(identifierAuthorityParts[2])

	subAuthority := make([]uint32, subAuthorityCount)
	if err := binary.Read(reader, binary.LittleEndian, &subAuthority); err != nil {
		return "", errors.Wrapf(err, "SID %#v convert failed reading SubAuthority", b)
	}

	result := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)
	for _, subAuthorityPart := range subAuthority {
		result += fmt.Sprintf("-%d", subAuthorityPart)
	}

	return result, nil
}

func parseCN(dn string) string {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil || len(parsedDN.RDNs) == 0 {
		// Allready a CN
		return dn
	}

	for _, rdn := range parsedDN.RDNs {
		for _, rdnAttr := range rdn.Attributes {
			if strings.EqualFold(rdnAttr.Type, "CN") {
				return rdnAttr.Value
			}
		}
	}
	return dn
}
