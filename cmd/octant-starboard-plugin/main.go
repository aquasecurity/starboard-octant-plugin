package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	security "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/octant-starboard-plugin/pkg/data"
	"github.com/aquasecurity/octant-starboard-plugin/pkg/view"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	pluginName        = "starboard"
	pluginDescription = "Kubernetes-native security"
)

var (
	nodeGVK       = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}
	podGVK        = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	deploymentGVK = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	daemonSetGVK  = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}
	namespaceGVK  = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}
)

func main() {
	if err := run(os.Args); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run(_ []string) (err error) {
	log.SetPrefix("")

	capabilities := &plugin.Capabilities{
		SupportsTab:           []schema.GroupVersionKind{podGVK, deploymentGVK, daemonSetGVK, namespaceGVK, nodeGVK},
		SupportsPrinterConfig: []schema.GroupVersionKind{podGVK, deploymentGVK, daemonSetGVK},
		IsModule:              false,
	}
	options := []service.PluginOption{
		service.WithTabPrinter(handleVulnerabilitiesTab),
		service.WithPrinter(handlePrinterConfig),
	}
	p, err := service.Register(pluginName, pluginDescription, capabilities, options...)
	if err != nil {
		return
	}
	p.Serve()
	return
}

// handleVulnerabilitiesTab is called when Octant want to print the Vulnerabilities tab.
func handleVulnerabilitiesTab(request *service.PrintRequest) (tag plugin.TabResponse, err error) {
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
	case data.WorkloadKindPod, data.WorkloadKindDeployment, data.WorkloadKindDaemonSet:
		return handleVulnerabilitiesTabForWorkload(request, data.Workload{Kind: kind, Name: name})
	case data.KindNamespace:
		return handleVulnerabilitiesTabForNamespace(request, name)
	case data.KindNode:
		return handleCISBenchmarkTabForNode(request, name)
	}

	return
}

func handleVulnerabilitiesTabForWorkload(request *service.PrintRequest, workload data.Workload) (tabResponse plugin.TabResponse, err error) {
	repository := data.NewRepository(request.DashboardClient)
	reports, err := repository.GetVulnerabilitiesForWorkload(request.Context(), workload)
	if err != nil {
		return
	}

	tab := component.NewTabWithContents(view.NewVulnerabilitiesReport(reports))
	tabResponse = plugin.TabResponse{Tab: tab}

	return
}

func handleVulnerabilitiesTabForNamespace(request *service.PrintRequest, namespace string) (tabResponse plugin.TabResponse, err error) {
	repository := data.NewRepository(request.DashboardClient)
	reports, err := repository.GetVulnerabilitiesForNamespace(request.Context(), namespace)
	if err != nil {
		return
	}
	tab := component.NewTabWithContents(view.NewVulnerabilitiesReport([]data.ContainerImageScanReport{reports}))
	tabResponse = plugin.TabResponse{Tab: tab}
	return
}

func handleCISBenchmarkTabForNode(request *service.PrintRequest, node string) (tabResponse plugin.TabResponse, err error) {
	repository := data.NewRepository(request.DashboardClient)
	report, err := repository.GetCISKubernetesBenchmark(request.Context(), node)
	if err != nil {
		return
	}

	tab := component.NewTabWithContents(view.NewCISKubernetesBenchmarksReport(report))
	tabResponse = plugin.TabResponse{Tab: tab}
	return
}

// handlePrinterConfig is called when Octant wants to print an object.
func handlePrinterConfig(request *service.PrintRequest) (plugin.PrintResponse, error) {
	if request.Object == nil {
		return plugin.PrintResponse{}, errors.New("object is nil")
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

	printItems = append(printItems, component.FlexLayoutItem{
		Width: component.WidthHalf,
		View:  view.NewVulnerabilitiesSummary("Vulnerabilities", summary),
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

func summarySectionsFor(summary security.VulnerabilitySummary) []component.SummarySection {
	return []component.SummarySection{
		{Header: "Critical Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.CriticalCount))},
		{Header: "High Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.HighCount))},
		{Header: "Medium Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.MediumCount))},
		{Header: "Low Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.LowCount))},
		{Header: "Unknown Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.UnknownCount))},
	}
}
