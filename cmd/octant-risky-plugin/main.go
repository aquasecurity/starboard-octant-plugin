package main

import (
	"fmt"
	security "github.com/aquasecurity/k8s-security-crds/pkg/apis/security/v1alpha1"
	"github.com/aquasecurity/octant-risky-plugin/pkg/data"
	"github.com/aquasecurity/octant-risky-plugin/pkg/view"
	"github.com/pkg/errors"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"log"
	"strconv"
	"time"
)

func main() {
	log.SetPrefix("")

	podGVK := schema.GroupVersionKind{Version: "v1", Kind: "Pod"}

	capabilities := &plugin.Capabilities{
		SupportsTab:           []schema.GroupVersionKind{podGVK},
		SupportsPrinterConfig: []schema.GroupVersionKind{podGVK},
		IsModule:              false,
	}
	options := []service.PluginOption{
		service.WithTabPrinter(handleTab),
		service.WithPrinter(handlePrint),
	}
	p, err := service.Register("risky", "Kubernetes-native risk explorer plugin", capabilities, options...)
	if err != nil {
		log.Fatal(err)
	}
	p.Serve()
}

func handleTab(request *service.PrintRequest) (plugin.TabResponse, error) {
	if request.Object == nil {
		return plugin.TabResponse{}, errors.New("object is nil")
	}

	pod, err := data.UnstructuredToPod(request.Object.(*unstructured.Unstructured))
	if err != nil {
		return plugin.TabResponse{}, err
	}

	repository := data.NewRepository(request.DashboardClient)
	reports, err := repository.GetImageScanReports(request.Context(), data.Workload{
		Kind: "Pod",
		Name: pod.Name,
	})
	if err != nil {
		return plugin.TabResponse{}, err
	}

	tab := createVulnerabilitiesTab(reports)

	return plugin.TabResponse{Tab: tab}, nil
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

// handlePrint is called when Octant wants to print an object.
func handlePrint(request *service.PrintRequest) (plugin.PrintResponse, error) {
	if request.Object == nil {
		return plugin.PrintResponse{}, errors.Errorf("object is nil")
	}

	// load an object from the cluster and use that object to create a response.

	// Octant has a helper function to generate a key from an object. The key
	// is used to find the object in the cluster.
	key, err := store.KeyFromObject(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, err
	}
	unstructuredPod, found, err := request.DashboardClient.Get(request.Context(), key)
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	// The plugin can check if the object it requested exists.
	if !found {
		return plugin.PrintResponse{}, errors.New("object doesn't exist")
	}

	repository := data.NewRepository(request.DashboardClient)

	var printItems []component.FlexLayoutItem

	printItems = append(printItems, component.FlexLayoutItem{
		Width: component.WidthHalf,
		View:  view.NewDebug("THIS IS A TEST"),
	})

	summary, err := repository.GetVulnerabilitiesSummary(request.Context(), data.Workload{
		Kind: "Pod",
		Name: unstructuredPod.GetName(),
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
