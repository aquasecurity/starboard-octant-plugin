SHELL = /bin/bash

.PHONY: build
build:
	go build -o bin/octant-terra-nova cmd/octant-terra-nova/main.go
