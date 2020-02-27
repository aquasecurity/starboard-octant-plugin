package main

import (
	"fmt"
	security "github.com/aquasecurity/k8s-security-crds/pkg/apis/security/v1alpha1"
	"github.com/aquasecurity/octant-risky-plugin/pkg/data"
	"github.com/aquasecurity/octant-risky-plugin/pkg/view"
	"github.com/pkg/errors"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"log"
	"strconv"
	"time"
)

func main() {
	log.SetPrefix("")

	podGVK := schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
	deploymentGVK := schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}

	capabilities := &plugin.Capabilities{
		SupportsTab:           []schema.GroupVersionKind{podGVK, deploymentGVK},
		SupportsPrinterConfig: []schema.GroupVersionKind{podGVK, deploymentGVK},
		IsModule:              false,
	}
	options := []service.PluginOption{
		service.WithTabPrinter(handleTab),
		service.WithPrinter(handlePrinterConfig),
	}
	p, err := service.Register("risky", "Kubernetes-native risk explorer plugin", capabilities, options...)
	if err != nil {
		log.Fatal(err)
	}
	p.Serve()
}

func handleTab(request *service.PrintRequest) (tab plugin.TabResponse, err error) {
	if request.Object == nil {
		err = errors.New("object is nil")
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

	repository := data.NewRepository(request.DashboardClient)
	reports, err := repository.GetImageScanReports(request.Context(), data.Workload{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		return plugin.TabResponse{}, err
	}

	tab = plugin.TabResponse{Tab: createVulnerabilitiesTab(reports)}

	return
}

func createVulnerabilitiesTab(reports []data.ContainerImageScanReport) *component.Tab {
	flexLayout := component.NewFlexLayout("Vulnerabilities")
	var items []component.FlexLayoutItem
	for _, containerReport := range reports {
		items = append(items, component.FlexLayoutItem{
			Width: component.WidthFull,
			View:  view.NewImageScanReport(containerReport.Name, containerReport.Report),
		})
	}

	flexLayout.AddSections(items)

	return component.NewTabWithContents(*flexLayout)
}

// handlePrinterConfig is called when Octant wants to print an object.
func handlePrinterConfig(request *service.PrintRequest) (plugin.PrintResponse, error) {
	if request.Object == nil {
		return plugin.PrintResponse{}, errors.Errorf("object is nil")
	}

	repository := data.NewRepository(request.DashboardClient)

	var printItems []component.FlexLayoutItem

	printItems = append(printItems, component.FlexLayoutItem{
		Width: component.WidthHalf,
		View:  view.NewDebug(fmt.Sprintf("%v", request.Object)),
	})

	accessor := meta.NewAccessor()
	kind, err := accessor.Kind(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, err
	}
	name, err := accessor.Name(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	summary, err := repository.GetVulnerabilitiesSummary(request.Context(), data.Workload{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	vs := component.NewSummary("Vulnerabilities",
		summarySectionsFor(summary)...,
	)

	printItems = append(printItems, component.FlexLayoutItem{
		Width: component.WidthHalf,
		View:  vs,
	})

	// When printing an object, you can create multiple types of content. In this
	// example, the plugin is:
	//
	// * adding a field to the configuration section for this object.
	// * adding a field to the status section for this object.
	// * create a new piece of content that will be embedded in the
	//   summary section for the component.
	return plugin.PrintResponse{
		Config: []component.SummarySection{
			{Header: "Last Scanned At", Content: component.NewText(fmt.Sprintf("%s", time.Now().Format(time.RFC3339)))},
		},
		Status: summarySectionsFor(summary),
		Items:  printItems,
	}, nil
}

func summarySectionsFor(summary security.VulnerabilitiesSummary) []component.SummarySection {
	return []component.SummarySection{
		{Header: "Critical Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.CriticalCount))},
		{Header: "High Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.HighCount))},
		{Header: "Medium Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.MediumCount))},
		{Header: "Low Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.LowCount))},
		{Header: "Unknown Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.UnknownCount))},
	}
}
