package controller

import (
	"errors"
	"strconv"

	"github.com/aquasecurity/octant-starboard-plugin/pkg/plugin/model"

	"github.com/aquasecurity/octant-starboard-plugin/pkg/plugin/view"
	security "github.com/aquasecurity/starboard-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/api/meta"
)

// HandleVulnerabilitiesTab is called when Octant want to print the Vulnerabilities tab.
func HandleVulnerabilitiesTab(request *service.PrintRequest) (tag plugin.TabResponse, err error) {
	if request.Object == nil {
		err = errors.New("request object is nil")
		return
	}

	accessor := meta.NewAccessor()
	name, err := accessor.Name(request.Object)
	if err != nil {
		return
	}
	kind, err := accessor.Kind(request.Object)
	if err != nil {
		return
	}

	switch kind {
	case model.WorkloadKindPod, model.WorkloadKindDeployment, model.KindStatefulSet, model.WorkloadKindDaemonSet:
		return handleVulnerabilitiesTabForWorkload(request, model.Workload{Kind: kind, Name: name})
	case model.KindNamespace:
		return handleVulnerabilitiesTabForNamespace(request, name)
	case model.KindNode:
		return handleCISBenchmarkTabForNode(request, name)
	}

	return
}

func handleVulnerabilitiesTabForWorkload(request *service.PrintRequest, workload model.Workload) (tabResponse plugin.TabResponse, err error) {
	repository := model.NewRepository(request.DashboardClient)
	reports, err := repository.GetVulnerabilitiesForWorkload(request.Context(), workload)
	if err != nil {
		return
	}

	tab := component.NewTabWithContents(view.NewVulnerabilitiesReport(reports))
	tabResponse = plugin.TabResponse{Tab: tab}

	return
}

func handleVulnerabilitiesTabForNamespace(request *service.PrintRequest, namespace string) (tabResponse plugin.TabResponse, err error) {
	repository := model.NewRepository(request.DashboardClient)
	reports, err := repository.GetVulnerabilitiesForNamespace(request.Context(), namespace)
	if err != nil {
		return
	}
	tab := component.NewTabWithContents(view.NewVulnerabilitiesReport([]model.ContainerImageScanReport{reports}))
	tabResponse = plugin.TabResponse{Tab: tab}
	return
}

func handleCISBenchmarkTabForNode(request *service.PrintRequest, node string) (tabResponse plugin.TabResponse, err error) {
	repository := model.NewRepository(request.DashboardClient)
	report, err := repository.GetCISKubernetesBenchmark(request.Context(), node)
	if err != nil {
		return
	}

	tab := component.NewTabWithContents(view.NewCISKubernetesBenchmarksReport(report))
	tabResponse = plugin.TabResponse{Tab: tab}
	return
}

// handlePrinterConfig is called when Octant wants to print an object.
func HandlePrinterConfig(request *service.PrintRequest) (plugin.PrintResponse, error) {
	if request.Object == nil {
		return plugin.PrintResponse{}, errors.New("object is nil")
	}

	repository := model.NewRepository(request.DashboardClient)

	accessor := meta.NewAccessor()
	kind, err := accessor.Kind(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, err
	}
	name, err := accessor.Name(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	summary, err := repository.GetVulnerabilitiesSummary(request.Context(), model.Workload{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	configAudit, err := repository.GetConfigAudit(request.Context(), model.Workload{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	// When printing an object, you can create multiple types of content. In this
	// example, the plugin is:
	//
	// * adding a field to the configuration section for this object.
	// * adding a field to the status section for this object.
	// * create a new piece of content that will be embedded in the
	//   summary section for the component.
	return plugin.PrintResponse{
		Status: summarySectionsFor(summary),
		Items: []component.FlexLayoutItem{
			{
				Width: component.WidthFull,
				View:  view.NewPolarisReport(configAudit),
			},
		},
	}, nil
}

func summarySectionsFor(summary security.VulnerabilitySummary) []component.SummarySection {
	return []component.SummarySection{
		{Header: "Critical Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.CriticalCount))},
		{Header: "High Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.HighCount))},
		{Header: "Medium Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.MediumCount))},
		{Header: "Low Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.LowCount))},
		{Header: "Unknown Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.UnknownCount))},
	}
}
