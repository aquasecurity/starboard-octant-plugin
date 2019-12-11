package main

import (
	"encoding/json"
	"fmt"
	extensions "github.com/danielpacak/k8s-vulnerability-crd/pkg/apis/extensions/v1"
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
		IsModule:              true,
	}
	options := []service.PluginOption{
		service.WithTabPrinter(handleTab),
		service.WithPrinter(handlePrint),
	}
	p, err := service.Register("terra-nova", "A terra-nova plugin", capabilities, options...)
	if err != nil {
		log.Fatal(err)
	}
	p.Serve()
}

func handleTab(request *service.PrintRequest) (plugin.TabResponse, error) {
	if request.Object == nil {
		return plugin.TabResponse{}, errors.New("object is nil")
	}

	ctx := request.Context()
	client := request.DashboardClient

	ul, err := client.List(ctx, store.Key{
		APIVersion: "extensions.aquasec.com/v1",
		Kind:       "Vulnerability",
	})

	if err != nil {
		return plugin.TabResponse{}, err
	}

	text, err := json.Marshal(request.Object)
	if err != nil {
		return plugin.TabResponse{}, err
	}

	items := unstructuredListToVulnerabilityItems(ul)
	tab := createVulnerabilitiesTab(string(text), items)

	return plugin.TabResponse{Tab: tab}, nil
}

func unstructuredToVulnerabilityItem(ui unstructured.Unstructured) (vi extensions.VulnerabilitySpec, err error) {
	vulnerabilityId, _, err := unstructured.NestedString(ui.Object, "spec", "vulnerabilityId")
	if err != nil {
		return
	}
	installedVersion, _, err := unstructured.NestedString(ui.Object, "spec", "installedVersion")
	if err != nil {
		return
	}
	fixedVersion, _, err := unstructured.NestedString(ui.Object, "spec", "fixedVersion")
	if err != nil {
		return
	}
	severity, _, err := unstructured.NestedString(ui.Object, "spec", "severity")
	if err != nil {
		return
	}
	resource, _, err := unstructured.NestedString(ui.Object, "spec", "resource")
	if err != nil {
		return
	}
	title, _, err := unstructured.NestedString(ui.Object, "spec", "title")
	if err != nil {
		return
	}
	vi = extensions.VulnerabilitySpec{
		VulnerabilityId:  vulnerabilityId,
		Severity:         severity,
		Resource:         resource,
		InstalledVersion: installedVersion,
		FixedVersion:     fixedVersion,
		Title:            title,
	}
	return
}

func unstructuredListToVulnerabilityItems(ul *unstructured.UnstructuredList) []extensions.VulnerabilitySpec {
	var items []extensions.VulnerabilitySpec
	for _, ui := range ul.Items {
		item, err := unstructuredToVulnerabilityItem(ui)
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		items = append(items, item)
	}
	return items
}

func createVulnerabilitiesTab(text string, vulnerabilityItems []extensions.VulnerabilitySpec) *component.Tab {
	header := component.NewMarkdownText(fmt.Sprintf(`## Vulnerabilities

Imagine that we list all containers and show vulnerabilities found by _Trivy_ operator.

%s
`, text))

	table := component.NewTableWithRows(
		"Vulnerabilities", "There are no vulnerabilities!",
		component.NewTableCols("ID", "Resource", "Installed Version", "Fixed Version", "Severity", "Title"),
		[]component.TableRow{})

	for _, vi := range vulnerabilityItems {
		tr := component.TableRow{
			"ID":                component.NewLink(vi.VulnerabilityId, vi.VulnerabilityId, fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", vi.VulnerabilityId)),
			"Severity":          component.NewText(vi.Severity),
			"Resource":          component.NewText(vi.Resource),
			"Installed Version": component.NewText(vi.InstalledVersion),
			"Fixed Version":     component.NewText(vi.FixedVersion),
			"Title":             component.NewText(vi.Title),
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
	podCard := component.NewCard(fmt.Sprintf("Extra Output for %s", u.GetName()))
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
			{Header: "Critical Severity Vulnerabilities", Content: component.NewText(strconv.Itoa(13))},
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
