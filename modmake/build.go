package main

import (
	. "github.com/saylorsolutions/modmake"
)

const (
	xorgenVersion = "1.1.2"
)

func main() {
	b := NewBuild()
	b.Generate().DependsOnRunner("tidy", "", Go().ModTidy())

	xorgen := NewAppBuild("xorgen", "cmd/xorgen", xorgenVersion)
	xorgen.Build(func(gb *GoBuild) {
		gb.
			StripDebugSymbols().
			SetVariable("main", "version", xorgenVersion).
			CgoEnabled(false)
	})
	xorgen.Variant("windows", "amd64")
	xorgen.Variant("linux", "amd64")
	xorgen.Variant("linux", "arm64")
	xorgen.Variant("darwin", "amd64")
	xorgen.Variant("darwin", "arm64")
	b.ImportApp(xorgen)

	b.Execute()
}
