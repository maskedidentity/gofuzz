#!/bin/bash
echo "Building GoFuzz..."
go mod init gofuzz
go mod tidy
go build -o gofuzz main.go
echo "Build complete! Run: ./gofuzz --help"
