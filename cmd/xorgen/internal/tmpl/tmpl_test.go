//go:generate xorgen -Ec -p tmpl test.txt
package tmpl

import (
	"github.com/stretchr/testify/assert"
	"io"
	"strings"
	"testing"
)

func TestUnscreenTest_txt(t *testing.T) {
	data, err := UnscreenTest_txt()
	assert.NoError(t, err)
	assert.Equal(t, "A test message that should be screened", string(data))
}

func TestStreamTest_txt(t *testing.T) {
	r, err := StreamTest_txt()
	assert.NoError(t, err)
	var buf strings.Builder
	_, err = io.Copy(&buf, r)
	assert.NoError(t, err)
	assert.Equal(t, "A test message that should be screened", buf.String())
}
