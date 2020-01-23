SHELL = /bin/bash
OCTANT_PLUGINS_DIR = ~/.config/octant/plugins

.PHONY: build
build:
	go build -o bin/octant-risky-plugin cmd/octant-risky-plugin/main.go

deploy: build
	mkdir -p $(OCTANT_PLUGINS_DIR)
	cp -vi bin/octant-risky-plugin $(OCTANT_PLUGINS_DIR)

.PHONY: uninstall
uninstall:
	rm -i $(OCTANT_PLUGINS_DIR)/octant-risky-plugin
