package settings

const (
	// This should stay lowercase for routing purposes
	name        = "starboard"
	description = "Kubernetes-native security"
	// See https://clarity.design/icons for all options
	rootNavIcon = "boat"
)

func GetName() string {
	return name
}

func GetDescription() string {
	return description
}
