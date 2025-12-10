package pki

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHost(t *testing.T) {
	tests := map[string]struct {
		given     string
		expected  string
		expectErr bool
	}{
		"Plain URL": {
			given:     "https://google.com/something/here",
			expected:  "",
			expectErr: true,
		},
		"Just host": {
			given:    "google.com",
			expected: "google.com",
		},
		"Host and port": {
			given:    "google.com:443",
			expected: "google.com",
		},
		"Path only": {
			given:     "/something/here",
			expected:  "",
			expectErr: true,
		},
		"Wildcard host": {
			given:    "*.google.com",
			expected: "*.google.com",
		},
		"Double scheme": {
			given:     "https://https://google.com",
			expected:  "",
			expectErr: true,
		},
		"Empty host": {
			given:     "",
			expected:  "",
			expectErr: true,
		},
		"Malformed with missing scheme": {
			given:     "://google.com/something/here",
			expected:  "",
			expectErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Log("Given:", tc.given)
			host, err := ParseHost(tc.given)
			if tc.expectErr {
				assert.Error(t, err)
				t.Log(err)
			} else {
				require.NoError(t, err)
			}
			t.Logf("Returned host name: '%s'", host)
			assert.Equal(t, tc.expected, host)
		})
	}
}
