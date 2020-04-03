package settings

import (
	"strings"

	"github.com/aquasecurity/octant-starboard-plugin/pkg/plugin/controller"
	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
)

func GetOptions() []service.PluginOption {
	return []service.PluginOption{
		service.WithTabPrinter(controller.HandleVulnerabilitiesTab),
		service.WithPrinter(controller.HandlePrinterConfig),
		service.WithNavigation(
			func(_ *service.NavigationRequest) (navigation.Navigation, error) {
				return navigation.Navigation{
					Title:    strings.Title(name),
					Path:     name,
					IconName: rootNavIcon,
				}, nil
			},
			controller.InitRoutes,
		),
	}
}
