package pki

import (
	"crypto/x509/pkix"
)

// NameBuilder is a convenient builder for creating a pkix.Name, without having to deal with the slices directly.
// Multiple values for the same field will be appended.
//
// A pkix.Name is used to identify the originating party of a certificate, and may be used as a static identity for the life of the certificate.
// With effective Public Key Infrastructure (PKI) automation, certificates can be short-lived to better reflect the realities of evolving organizational identity.
type NameBuilder struct {
	name pkix.Name
}

func (b *NameBuilder) Country(country string) *NameBuilder {
	b.name.Country = append(b.name.Country, country)
	return b
}

func (b *NameBuilder) Organization(org string) *NameBuilder {
	b.name.Organization = append(b.name.Organization, org)
	return b
}

func (b *NameBuilder) OrganizationalUnit(unit string) *NameBuilder {
	b.name.OrganizationalUnit = append(b.name.OrganizationalUnit, unit)
	return b
}

func (b *NameBuilder) Province(prov string) *NameBuilder {
	b.name.Province = append(b.name.Province, prov)
	return b
}

func (b *NameBuilder) StreetAddress(streetAddr string) *NameBuilder {
	b.name.StreetAddress = append(b.name.StreetAddress, streetAddr)
	return b
}

func (b *NameBuilder) PostalCode(postalCode string) *NameBuilder {
	b.name.PostalCode = append(b.name.PostalCode, postalCode)
	return b
}

func (b *NameBuilder) SerialNumber(serial string) *NameBuilder {
	b.name.SerialNumber = serial
	return b
}

func (b *NameBuilder) CommonName(name string) *NameBuilder {
	b.name.CommonName = name
	return b
}

func (b *NameBuilder) Build() pkix.Name {
	return b.name
}
