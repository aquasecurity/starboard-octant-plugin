package controller

import (
	"fmt"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/kubehunter"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/model"

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

	repository := model.NewRepository(request.DashboardClient())
	report, err := repository.GetKubeHunterReport(request.Context())
	if err != nil {
		return nil, err
	}

	flexLayout.AddSections(component.FlexLayoutSection{
		{Width: component.WidthFull, View: component.NewMarkdownText(fmt.Sprintf("## Starboard"))},
		{Width: component.WidthFull, View: component.NewMarkdownText(fmt.Sprintf("### Kube Hunter Report"))},
		{Width: component.WidthFull, View: kubehunter.NewReport(report)},
	})

	return flexLayout, nil
}
