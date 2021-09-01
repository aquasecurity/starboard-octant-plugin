package settings

import (
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/actions"
	"strings"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/controller"
	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
)

func GetOptions() []service.PluginOption {
	return []service.PluginOption{
		service.WithTabPrinter(controller.ResourceTabPrinter, controller.ResourceReportTabPrinter),
		service.WithPrinter(controller.ResourcePrinter),
		service.WithObjectStatus(controller.ResourceObjectStatus),
		service.WithActionHandler(actions.ActionHandler),
		service.WithNavigation(
			func(_ *service.NavigationRequest) (nav navigation.Navigation, err error) {
				nav = navigation.Navigation{
					Title:    strings.Title(name),
					Path:     name,
					IconName: rootNavIcon,
				}
				return
			},
			controller.InitRoutes,
		),
	}
}
