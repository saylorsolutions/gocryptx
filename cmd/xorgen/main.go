package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/saylorsolutions/gocryptx/cmd/xorgen/internal/tmpl"
	flag "github.com/spf13/pflag"
	"io"
	"os"
	"strings"
)

func main() {
	var (
		helpFlag     bool
		exposedFlag  bool
		compressFlag bool
	)
	flags := flag.NewFlagSet("xorgen", flag.ContinueOnError)
	flags.BoolVarP(&helpFlag, "help", "h", false, "Prints this usage information.")
	flags.BoolVarP(&exposedFlag, "exposed", "E", false, "Make the unscreen function exposed from the file. It's recommended to only expose from within an internal package.")
	flags.BoolVarP(&compressFlag, "compressed", "c", false, "Payload should be gzip compressed when embedded, which includes a checksum to help prevent tampering.")
	flags.Usage = func() {
		fmt.Printf(`
xorgen generates code to embed XOR obfuscated (and optionally compressed) data by generating a *.go file based on the input file. This pairs well with go:generate comments.
The name of the generated Go file will be based on the name of the input file, replacing characters that match the regex pattern [^a-zA-Z0-9_] with "_".
For example, given a file called super-secret.txt, a Go file will be created in the current directory called super_secret_txt.go, containing a function called unscreenSuper_secret_txt.
See the -E flag below to make it an exposed function, and make sure you review the SECURITY notes below if you're unfamiliar with XOR screening.

USAGE:  xorgen FILE [KEY]

Note: If a key argument is given, it will be used with offset 0.

ARGS:
    FILE is the input file to be embedded.
    KEY is optional and may be specified to override secure random generation behavior.

FLAGS:
%s
SECURITY:
    This is not encryption, this is obfuscation, and they are very different things!
XOR screening is intended to hide embedded data from passive binary analysis only, since XOR screening is easily reversible.
It's noteworthy that using gzip compression could make part of the XOR key easier to recover, since the gzip header is somewhat predictable.
This isn't really important to the threat model of this obfuscation method, since the plain text key is stored right next to the screened data.
`, flags.FlagUsages())
	}
	if len(os.Args) == 1 {
		flags.Usage()
		return
	}
	if err := flags.Parse(os.Args[1:]); err != nil {
		flags.Usage()
		fatal("Error parsing flags: %v", err)
	}
	if helpFlag {
		flags.Usage()
		return
	}

	switch flags.NArg() {
	case 0:
		fatal("Missing required FILE argument")
	case 1:
		err := tmpl.GenerateFile(
			flags.Arg(0),
			tmpl.RandomKey(),
			tmpl.CompressData(compressFlag),
			tmpl.ExposeFunctions(exposedFlag),
		)
		if err != nil {
			fatal("Failed to generate file: %v", err)
		}
	default:
		var key bytes.Buffer
		_, err := io.Copy(&key, hex.NewDecoder(strings.NewReader(flags.Arg(1))))
		if err != nil {
			fatal("Failed to decode KEY, must be a hex string with only the characters a-f, A-F, or 0-9")
		}
		err = tmpl.GenerateFile(
			flags.Arg(0),
			tmpl.UseKeyOffset(key.Bytes(), 0),
			tmpl.CompressData(compressFlag),
			tmpl.ExposeFunctions(exposedFlag),
		)
		if err != nil {
			fatal("Failed to generate file: %v", err)
		}
	}
}

func fatal(msg string, args ...any) {
	echo(msg, args...)
	os.Exit(1)
}

func echo(msg string, args ...any) {
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Printf(msg, args...)
}
