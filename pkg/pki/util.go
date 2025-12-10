package pki

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var leadingScheme = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// ParseHost is used to parse and validate the host portion of a string for use as a Subject Alternative Name (SAN).
// It's intended to accept many different values that may be easily coerced into a valid SAN host name.
func ParseHost(given string) (string, error) {
	orig := given
	given = strings.TrimSpace(given)
	if len(given) == 0 {
		return "", fmt.Errorf("empty host name given")
	}
	wildcard := false
	if strings.HasPrefix(given, "*.") {
		wildcard = true
		given = strings.TrimPrefix(given, "*.")
	}
	if leadingScheme.MatchString(given) {
		return "", fmt.Errorf("expected host name without scheme: '%s'", orig)
	}
	given = "https://" + given
	u, err := url.ParseRequestURI(given)
	if err != nil {
		return "", err
	}
	if len(u.Host) == 0 {
		return "", fmt.Errorf("paths are not valid hostnames: '%s'", orig)
	}
	if host, _, err := net.SplitHostPort(u.Host); err == nil {
		if wildcard {
			return "*." + host, nil
		}
		if len(host) == 0 {
			return "", fmt.Errorf("invalid hostname: '%s'", orig)
		}
		return host, nil
	}
	if wildcard {
		return "*." + u.Host, nil
	}
	return u.Host, nil
}
