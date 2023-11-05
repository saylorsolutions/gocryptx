package main

import (
	. "github.com/saylorsolutions/modmake"
)

const (
	xorgenVersion = "1.0.2"
)

var (
	xorgenBuildPath   = Path("build/xorgen")
	xorgenPackagePath = Path("dist/xorgen")
)

func main() {
	b := NewBuild()
	b.Generate().DependsOnRunner("tidy", "", Go().ModTidy())
	b.Test().Does(
		Script(
			Go().Clean().TestCache(), // Some of these tests can be a bit flaky, not sure why.
			Go().TestAll(),
		),
	)
	b.Build().DependsOnRunner("clean-build", "", RemoveDir(Path("build/xorgen")))
	b.Package().DependsOnRunner("clean-dist", "", RemoveDir(Path("dist/xorgen")))

	xorgenVariants := map[string][]string{
		"windows": {"amd64"},
		"linux":   {"amd64", "arm64"},
		"darwin":  {"amd64", "arm64"},
	}
	for os, archs := range xorgenVariants {
		for _, arch := range archs {
			variant := "xorgen-" + os + "-" + arch
			imported := xorgenBuild(os, arch)
			b.Import(variant, imported)
			b.Build().DependsOn(imported.Build())
			b.Package().DependsOn(imported.Package())
		}
	}
	b.Package().AfterRun(RemoveDir(Path("build/xorgen")))

	b.Execute()
}

func xorgenBuild(os, arch string) *Build {
	outputFile := "xorgen"
	qualifier := os + "_" + arch
	if os == "windows" {
		outputFile += ".exe"
	}
	outputPath := xorgenBuildPath.Join(qualifier, outputFile)
	b := NewBuild()
	build := Go().Build(Go().ToModulePath("cmd/xorgen")).
		OS(os).Arch(arch).
		OutputFilename(outputPath).
		StripDebugSymbols().
		SetVariable("main", "version", xorgenVersion)
	b.Build().Does(build)
	b.Build().DependsOnRunner("create-build-dir", "", MkdirAll(outputPath.Dir(), 0600))

	var pkg Runner
	if os == "windows" {
		pkg = Zip(xorgenPackagePath.Join("xorgen-"+qualifier+"-"+xorgenVersion+".zip")).
			AddFileWithPath(outputPath, "xorgen.exe").
			Create()
	} else {
		pkg = Tar(xorgenPackagePath.Join("xorgen-"+qualifier+"-"+xorgenVersion+".tar.gz")).
			AddFileWithPath(outputPath, "xorgen").
			Create()
	}
	b.Package().Does(pkg)
	b.Package().DependsOnRunner("create-pkg-dir", "", MkdirAll(xorgenPackagePath, 0600))
	return b
}
