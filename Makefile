SHELL = /bin/bash
OCTANT_PLUGINS_DIR = ~/.config/octant/plugins

.PHONY: build
build:
	go build -mod=vendor -o bin/octant-starboard-plugin cmd/octant-starboard-plugin/main.go

deploy: build
	mkdir -p $(OCTANT_PLUGINS_DIR)
	cp -vi bin/octant-starboard-plugin $(OCTANT_PLUGINS_DIR)

.PHONY: uninstall
uninstall:
	rm -i $(OCTANT_PLUGINS_DIR)/octant-starboard-plugin
