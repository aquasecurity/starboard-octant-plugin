package controller

import (
	"errors"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/configaudit"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/kubebench"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/vulnerabilities"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/model"

	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/api/meta"
)

// TODO Rename to more generic name; it's not only for vulnerabilities but other kinds of reports such as CIS Kubernetes Benchmarks
// HandleVulnerabilitiesTab is called when Octant want to print the Vulnerabilities tab.
func HandleVulnerabilitiesTab(request *service.PrintRequest) (tab plugin.TabResponse, err error) {
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
	namespace, err := accessor.Namespace(request.Object)
	if err != nil {
		return
	}

	switch kind {
	case model.WorkloadKindPod,
		model.WorkloadKindDeployment,
		model.WorkloadKindDaemonSet,
		model.StatefulSetKind,
		model.ReplicaSetKind,
		model.ReplicationControllerKind,
		model.CronJobKind,
		model.JobKind:
		return handleVulnerabilitiesTabForWorkload(request, model.Workload{Kind: kind, Name: name, Namespace: namespace})
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

	tab := component.NewTabWithContents(vulnerabilities.NewReport(workload, reports))
	tabResponse = plugin.TabResponse{Tab: tab}

	return
}

func handleCISBenchmarkTabForNode(request *service.PrintRequest, node string) (tabResponse plugin.TabResponse, err error) {
	repository := model.NewRepository(request.DashboardClient)
	report, err := repository.GetCISKubeBenchReport(request.Context(), node)
	if err != nil {
		return
	}

	tab := component.NewTabWithContents(kubebench.NewReport(report))
	tabResponse = plugin.TabResponse{Tab: tab}
	return
}

// handlePrinterConfig is called when Octant wants to print an object.
func HandlePrinterConfig(request *service.PrintRequest) (response plugin.PrintResponse, err error) {
	if request.Object == nil {
		err = errors.New("object is nil")
		return
	}

	repository := model.NewRepository(request.DashboardClient)

	accessor := meta.NewAccessor()
	kind, err := accessor.Kind(request.Object)
	if err != nil {
		return
	}
	name, err := accessor.Name(request.Object)
	if err != nil {
		return
	}

	summary, err := repository.GetVulnerabilitiesSummary(request.Context(), model.Workload{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		return
	}

	configAudit, err := repository.GetConfigAudit(request.Context(), model.Workload{
		Kind: kind,
		Name: name,
	})
	if err != nil {
		return
	}

	response = plugin.PrintResponse{
		Status: vulnerabilities.NewSummarySections(summary),
		Items: []component.FlexLayoutItem{
			{
				Width: component.WidthFull,
				View:  configaudit.NewReport(configAudit),
			},
		},
	}
	return
}
