package tmpl

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"github.com/saylorsolutions/gocryptx/pkg/xor"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"text/template"
	"unicode"
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
	Compress       bool
	FileMethodName string
	KeyString      string
	DataString     string
	Offset         int
	keyData        []byte
	fileData       []byte
}

func GenerateFile(params *Params, err error) error {
	if err != nil {
		return err
	}
	out, err := os.Create(uniuncap(params.FileMethodName) + ".go")
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

func SetKey(file string, exposed bool, compress bool, key []byte, offset int) (*Params, error) {
	params := &Params{
		Exposed:  exposed,
		Compress: compress,
		Offset:   offset,
	}
	if err := populateContextData(params); err != nil {
		return nil, err
	}
	_, err := populateFileData(params, file)
	if err != nil {
		return nil, err
	}
	params.keyData = key
	if err := screenData(params); err != nil {
		return nil, err
	}
	return params, nil
}

func RandomKeyOffset(file string, exposed bool, compress bool) (*Params, error) {
	params := &Params{
		Exposed:  exposed,
		Compress: compress,
	}
	if err := populateContextData(params); err != nil {
		return nil, err
	}
	length, err := populateFileData(params, file)
	if err != nil {
		return nil, err
	}
	var (
		key    []byte
		offset int
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
		return nil, err
	}
	params.keyData = key
	params.Offset = offset
	if err := screenData(params); err != nil {
		return nil, err
	}
	return params, nil
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

func populateFileData(params *Params, file string) (int, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}

	if params.Compress {
		var buf bytes.Buffer
		w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return 0, err
		}
		_, err = w.Write(data)
		if err != nil {
			return 0, err
		}
		if err := w.Close(); err != nil {
			return 0, err
		}
		data = buf.Bytes()
	}
	params.fileData = data

	_, fname := filepath.Split(file)
	params.FileMethodName = fileCleansePattern.ReplaceAllString(unicap(fname), "_")
	return len(data), nil
}

func screenData(params *Params) error {
	var buf bytes.Buffer
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

func uniuncap(s string) string {
	runes := []rune(s)
	switch len(runes) {
	case 0:
		return ""
	case 1:
		return string(unicode.ToLower(runes[0]))
	default:
		return string(append([]rune{unicode.ToLower(runes[0])}, runes[1:]...))
	}
}
