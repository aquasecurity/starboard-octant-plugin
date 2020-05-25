package settings

import (
	"fmt"
)

const (
	// This should stay lowercase for routing purposes
	name        = "starboard"
	description = "Kubernetes-native security"
	// See https://clarity.design/icons for all options
	rootNavIcon = "boat"
)

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

func GetName() string {
	return name
}

func GetDescription(version VersionInfo) string {
	return fmt.Sprintf("%s (%s, %s, %s)", description, version.Version, version.Commit, version.Date)
}
