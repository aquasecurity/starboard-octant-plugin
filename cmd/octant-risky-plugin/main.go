package main

import (
	"encoding/json"
	"fmt"
	secv1 "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/pkg/errors"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
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

	// TODO Parse it to Pod
	pod := request.Object.(*unstructured.Unstructured)
	containers, _, _ := unstructured.NestedSlice(pod.Object, "spec", "containers")
	container := containers[0].(map[string]interface{})
	image, _, _ := unstructured.NestedString(container, "image")

	client := request.DashboardClient
	ul, err := client.List(request.Context(), store.Key{
		APIVersion: "security.danielpacak.github.com/v1",
		Kind:       "ImageScanReport",
		Selector: &labels.Set{
			"image-ref": image,
		},
	})
	if err != nil {
		return plugin.TabResponse{}, err
	}

	tab := createVulnerabilitiesTab(request.Object, ul)

	return plugin.TabResponse{Tab: tab}, nil
}

func createVulnerabilitiesTab(obj runtime.Object, ul *unstructured.UnstructuredList) *component.Tab {
	pod := obj.(*unstructured.Unstructured)
	containers, _, _ := unstructured.NestedSlice(pod.Object, "spec", "containers")
	container := containers[0].(map[string]interface{})
	image, _, _ := unstructured.NestedString(container, "image")

	header := component.NewMarkdownText(fmt.Sprintf(`## Vulnerabilities

Imagine that we list all containers and show vulnerabilities found by _Trivy_ operator.

%v`, image))

	table := component.NewTableWithRows(
		"Vulnerabilities", "There are no vulnerabilities!",
		component.NewTableCols("ID", "Severity", "Title", "Resource", "Installed Version", "Fixed Version"),
		[]component.TableRow{})

	vulnerabilityItems, _ := getVulnerabilities(ul)
	for _, vi := range vulnerabilityItems {
		tr := component.TableRow{
			"ID":                getLinkComponent(vi),
			"Severity":          component.NewText(vi.Severity),
			"Title":             component.NewText(vi.Title),
			"Resource":          component.NewText(vi.Resource),
			"Installed Version": component.NewText(vi.InstalledVersion),
			"Fixed Version":     component.NewText(vi.FixedVersion),
		}
		table.Add(tr)
	}

	table.Sort("ID", false)

	flexLayout := component.NewFlexLayout("Vulnerabilities")
	flexLayout.AddSections(component.FlexLayoutSection{
		{Width: component.WidthFull, View: header},
		{Width: component.WidthFull, View: table},
	})

	return component.NewTabWithContents(*flexLayout)
}

func getLinkComponent(vi secv1.VulnerabilitySpec) component.Component {
	if len(vi.Links) > 0 {
		return component.NewLink(vi.VulnerabilityID, vi.VulnerabilityID, vi.Links[0])
	}
	return component.NewText(vi.VulnerabilityID)
}

func getVulnerabilities(ul *unstructured.UnstructuredList) (list []secv1.VulnerabilitySpec, err error) {
	b, err := ul.MarshalJSON()
	if err != nil {
		return list, err
	}
	var vl secv1.ImageScanReportList
	err = json.Unmarshal(b, &vl)
	if err != nil {
		return list, err
	}
	for _, i := range vl.Items[0].Spec.Vulnerabilities {
		list = append(list, i)
	}
	return list, nil
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
	u, found, err := request.DashboardClient.Get(request.Context(), key)
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	// The plugin can check if the object it requested exists.
	if !found {
		return plugin.PrintResponse{}, errors.New("object doesn't exist")
	}

	// Octant has a component library that can be used to build content for a plugin.
	// In this case, the plugin is creating a card.
	podCard := component.NewCard([]component.TitleComponent{component.NewText(fmt.Sprintf("Extra Output for %s", u.GetName()))})
	podCard.SetBody(component.NewMarkdownText("This output was generated from _octant-sample-plugin_"))

	msg := fmt.Sprintf("%s", time.Now().Format(time.RFC3339))

	// When printing an object, you can create multiple types of content. In this
	// example, the plugin is:
	//
	// * adding a field to the configuration section for this object.
	// * adding a field to the status section for this object.
	// * create a new piece of content that will be embedded in the
	//   summary section for the component.
	return plugin.PrintResponse{
		Config: []component.SummarySection{
			{Header: "Last Scanned At", Content: component.NewText(msg)},
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
				View:  podCard,
			},
		},
	}, nil
}
