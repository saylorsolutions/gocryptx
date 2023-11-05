package internal

import (
	"fmt"
	"os"
	"strings"
)

// Fatal will Echo the message and os.Exit with code 1.
func Fatal(msg string, args ...any) {
	Echo(msg, args...)
	os.Exit(1)
}

// Echo will emit the given message without any logging formatting.
func Echo(msg string, args ...any) {
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	_, _ = fmt.Fprintf(os.Stderr, msg, args...)
}
