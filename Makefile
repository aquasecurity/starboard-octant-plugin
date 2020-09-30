SHELL = /bin/bash
OCTANT_PLUGINS_DIR = ~/.config/octant/plugins

.PHONY: build
build:
	go build -o bin/starboard-octant-plugin cmd/starboard-octant-plugin/main.go

install: build
	mkdir -p $(OCTANT_PLUGINS_DIR)
	cp -vi bin/starboard-octant-plugin $(OCTANT_PLUGINS_DIR)

.PHONY: uninstall
uninstall:
	rm -i $(OCTANT_PLUGINS_DIR)/starboard-octant-plugin

.PHONY: test
test:
	go test ./...
