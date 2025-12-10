package tmpl

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"unicode"

	"github.com/saylorsolutions/gocryptx/pkg/xor"
)

const (
	idealMinKeyLen = 20
)

var (
	//go:embed screen_embed.go.tmpl
	tmplText     string
	tmplTemplate = template.Must(template.New("template").Parse(tmplText))
)

type Params struct {
	Package        string
	Exposed        bool
	Compressed     bool
	FileMethodName string
	KeyString      string
	DataString     string
	Offset         int

	keyData        []byte
	fileData       []byte
	targetFileName string
}

// ParamOpt operates on Params in a standard and predictable way, and is used in GenerateFile.
// If any ParamOpt returns an error, then file generation ceases and the error is returned.
type ParamOpt = func(params *Params) error

// CompressData indicates that data should be compressed.
func CompressData(val ...bool) ParamOpt {
	return func(params *Params) error {
		if len(val) > 0 {
			params.Compressed = val[0]
			return nil
		}
		params.Compressed = true
		return nil
	}
}

// ExposeFunctions indicates that generated functions should be exposed.
func ExposeFunctions(val ...bool) ParamOpt {
	return func(params *Params) error {
		if len(val) > 0 {
			params.Exposed = val[0]
			return nil
		}
		params.Exposed = true
		return nil
	}
}

// UseKeyOffset sets a key to be used instead of generating one randomly.
func UseKeyOffset(key []byte, offset int) ParamOpt {
	return func(params *Params) error {
		params.keyData = key
		params.Offset = offset
		return nil
	}
}

// RandomKey generates a random key and offset based on the payload size.
func RandomKey() ParamOpt {
	return randomKey
}

// PackageName specifies the package name of the generated file.
// This is useful for cases where the expected package name doesn't match the name of the containing directory.
func PackageName(name string) ParamOpt {
	name = strings.TrimSpace(name)
	return func(params *Params) error {
		if len(name) == 0 {
			return nil
		}
		params.Package = name
		return nil
	}
}

// GenerateFile will generate a file embedding the input file with XOR screening.
// Various generation options may be passed as zero or more ParamOpt.
func GenerateFile(input string, opts ...ParamOpt) error {
	params := new(Params)
	if err := populateContextData(params); err != nil {
		return err
	}
	if err := populateFileData(params, input); err != nil {
		return err
	}

	for _, opt := range opts {
		if err := opt(params); err != nil {
			return err
		}
	}

	if len(params.keyData) == 0 {
		if err := randomKey(params); err != nil {
			return err
		}
	}
	if err := screenData(params); err != nil {
		return err
	}

	out, err := os.Create(params.targetFileName + ".go")
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	if err := tmplTemplate.Execute(out, params); err != nil {
		return err
	}
	return nil
}

func populateContextData(params *Params) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	params.Package = filepath.Base(cwd)
	return nil
}

var (
	fileCleansePattern = regexp.MustCompile(`[^a-zA-Z0-9_]`)
)

func populateFileData(params *Params, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	params.fileData = data
	_, fname := filepath.Split(file)
	params.FileMethodName = fileCleansePattern.ReplaceAllString(unicap(fname), "_")
	params.targetFileName = fileCleansePattern.ReplaceAllString(fname, "_")
	return nil
}

func randomKey(params *Params) error {
	var (
		key    []byte
		offset int
		err    error
		length = len(params.fileData)
	)
	switch {
	case length > 3*idealMinKeyLen:
		key, offset, err = xor.GenKeyAndOffset(length / 3)
	case length > 2*idealMinKeyLen:
		key, offset, err = xor.GenKeyAndOffset(length / 2)
	default:
		key, offset, err = xor.GenKeyAndOffset(length)
	}
	if err != nil {
		return err
	}
	params.keyData = key
	params.Offset = offset
	return nil
}

func screenData(params *Params) error {
	var buf bytes.Buffer

	if params.Compressed {
		var buf bytes.Buffer
		w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return err
		}
		_, err = w.Write(params.fileData)
		if err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		params.fileData = buf.Bytes()
	}

	w, err := xor.NewWriter(&buf, params.keyData, params.Offset)
	if err != nil {
		return err
	}
	_, err = w.Write(params.fileData)
	if err != nil {
		return err
	}
	params.KeyString = fmt.Sprintf("%#v", params.keyData)
	params.DataString = fmt.Sprintf("%#v", buf.Bytes())
	return nil
}

func unicap(s string) string {
	runes := []rune(s)
	switch len(runes) {
	case 0:
		return ""
	case 1:
		return string(unicode.ToUpper(runes[0]))
	default:
		return string(append([]rune{unicode.ToUpper(runes[0])}, runes[1:]...))
	}
}
