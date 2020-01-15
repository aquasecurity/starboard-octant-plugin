SHELL = /bin/bash
OCTANT_PLUGINS_DIR = ~/.config/octant/plugins

.PHONY: build
build:
	go build -o bin/octant-terra-nova cmd/octant-terra-nova/main.go

deploy: build
	mkdir -p $(OCTANT_PLUGINS_DIR)
	cp -vi bin/octant-terra-nova $(OCTANT_PLUGINS_DIR)
