package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

func newCommandFlagSet(name string, printUsage func()) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = printUsage
	return fs
}

func terminalText(value string) string {
	var out strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&out, `\x%02x`, value[0])
			value = value[1:]
			continue
		}
		if !unicode.IsPrint(r) {
			switch {
			case r <= 0xff:
				fmt.Fprintf(&out, `\x%02x`, r)
			case r <= 0xffff:
				fmt.Fprintf(&out, `\u%04x`, r)
			default:
				fmt.Fprintf(&out, `\U%08x`, r)
			}
		} else {
			out.WriteString(value[:size])
		}
		value = value[size:]
	}
	return out.String()
}

func quoteCommandArgument(value string) string {
	safe := terminalText(value)
	return "'" + strings.ReplaceAll(safe, "'", "'\"'\"'") + "'"
}

func pkgInspectSuggestion(goos, contentPath, signaturePath string) string {
	if goos == "windows" || terminalText(contentPath) != contentPath || terminalText(signaturePath) != signaturePath {
		return "Verify detached signatures with fortitool pkg inspect. " +
			"Run fortitool pkg inspect -h first; no copyable command is shown because the paths cannot be represented safely for the active platform."
	}
	return fmt.Sprintf("Verify detached signatures with e.g.:\n  fortitool pkg inspect --content %s %s",
		quoteCommandArgument(contentPath), quoteCommandArgument(signaturePath))
}
