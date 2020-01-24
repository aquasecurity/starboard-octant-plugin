package main

import (
	"fmt"
	security "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/danielpacak/octant-risky-plugin/pkg/data"
	"github.com/danielpacak/octant-risky-plugin/pkg/view"
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

	image := pod.Spec.Containers[0].Image

	repository := data.NewRepository(request.DashboardClient)
	report, err := repository.GetImageScanReportFor(request.Context(), image)
	if err != nil {
		return plugin.TabResponse{}, err
	}

	tab := createVulnerabilitiesTab(report)

	return plugin.TabResponse{Tab: tab}, nil
}

func createVulnerabilitiesTab(report *security.ImageScanReport) *component.Tab {
	flexLayout := component.NewFlexLayout("Vulnerabilities")
	flexLayout.AddSections(component.FlexLayoutSection{
		{
			Width: component.WidthFull,
			View:  view.NewImageScanReport(report),
		},
	})

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
	_, found, err := request.DashboardClient.Get(request.Context(), key)
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	// The plugin can check if the object it requested exists.
	if !found {
		return plugin.PrintResponse{}, errors.New("object doesn't exist")
	}

	repository := data.NewRepository(request.DashboardClient)
	report, err := repository.GetDescriptorScanReportFor(request.Context(), "nginx")
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	dsrComponent := view.NewDescriptorScanReport(report)

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
		Status: []component.SummarySection{
			{Header: "Critical Severity Vulnerabilities", Content: component.NewText(strconv.Itoa(15))},
			{Header: "High Severity Vulnerabilities", Content: component.NewText(strconv.Itoa(3))},
			{Header: "Medium Severity Vulnerabilities", Content: component.NewText(strconv.Itoa(7))},
			{Header: "Low Severity Vulnerabilities", Content: component.NewText(strconv.Itoa(1))},
		},
		Items: []component.FlexLayoutItem{
			{
				Width: component.WidthHalf,
				View:  dsrComponent,
			},
		},
	}, nil
}
