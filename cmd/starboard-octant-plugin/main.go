package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/settings"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
)

var (
	// Default wise GoReleaser sets three ldflags:
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.SetPrefix("")

	if err := run(os.Args); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run(_ []string) (err error) {
	name := settings.GetName()
	description := settings.GetDescription(settings.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	capabilities := settings.GetCapabilities()
	options := settings.GetOptions()
	plugin, err := service.Register(name, description, capabilities, options...)
	if err != nil {
		err = fmt.Errorf("registering %s plugin: %w", name, err)
		return
	}
	plugin.Serve()
	return
}
