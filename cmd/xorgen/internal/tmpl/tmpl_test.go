//go:generate xorgen -c test.txt
package tmpl

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnScreenTestTxt(t *testing.T) {
	data, err := unscreenTest_txt()
	assert.NoError(t, err)
	assert.Equal(t, "A test message that should be screened", string(data))
}
