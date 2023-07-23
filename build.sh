#!/usr/bin/env bash
source ./clean.sh
VERSION=1.0.0

GOOS=windows GOARCH=amd64 go build github.com/saylorsolutions/gocryptx/cmd/xorgen
zip xorgen_windows_amd64_${VERSION}.zip xorgen.exe
rm xorgen.exe

GOOS=linux GOARCH=amd64 go build github.com/saylorsolutions/gocryptx/cmd/xorgen
tar -czf xorgen_linux_amd64_${VERSION}.tar.gz xorgen
rm xorgen

GOOS=darwin GOARCH=amd64 go build github.com/saylorsolutions/gocryptx/cmd/xorgen
tar -czf xorgen_darwin_amd64_${VERSION}.tar.gz xorgen
rm xorgen

GOOS=darwin GOARCH=arm64 go build github.com/saylorsolutions/gocryptx/cmd/xorgen
tar -czf xorgen_darwin_arm64_${VERSION}.tar.gz xorgen
rm xorgen
