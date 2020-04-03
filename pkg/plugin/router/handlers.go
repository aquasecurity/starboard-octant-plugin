package router

import (
	"fmt"

	"github.com/aquasecurity/octant-starboard-plugin/pkg/data"

	"github.com/aquasecurity/octant-starboard-plugin/pkg/view"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func rootHandler(request service.Request) (component.ContentResponse, error) {
	rootView, err := buildRootViewForRequest(request)
	if err != nil {
		return component.EmptyContentResponse, err
	}
	response := component.NewContentResponse(nil)
	response.Add(rootView)
	return *response, nil
}

func buildRootViewForRequest(request service.Request) (*component.FlexLayout, error) {
	flexLayout := component.NewFlexLayout("")

	repository := data.NewRepository(request.DashboardClient())
	report, err := repository.GetKubeHunterReport(request.Context())
	if err != nil {
		return nil, err
	}

	flexLayout.AddSections(component.FlexLayoutSection{
		{Width: component.WidthFull, View: component.NewMarkdownText(fmt.Sprintf("## Starboard"))},
		{Width: component.WidthFull, View: component.NewMarkdownText(fmt.Sprintf("### Kube Hunter Report"))},
		{Width: component.WidthFull, View: view.NewKubeHunterReport(report.Report)},
	})

	return flexLayout, nil
}
