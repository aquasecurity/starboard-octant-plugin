package controller

import (
	"errors"
	"fmt"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/model"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/configaudit"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/kubebench"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

// PrimaryResourceTabPrinter is called when Octant wants to add a new tab for the underlying resource.
// For built-in K8s workloads the first tab renders a v1alpha1.VulnerabilityReport associated with each
// container, whereas for K8s Nodes it renders the v1alpha1.CISKubeBenchReport.
func PrimaryResourceTabPrinter(request *service.PrintRequest) (plugin.TabResponse, error) {
	if request.Object == nil {
		return plugin.TabResponse{}, errors.New("request object is nil")
	}

	object, err := getWorkloadFromObject(request.Object)
	if err != nil {
		return plugin.TabResponse{}, err
	}

	switch object.Kind {
	case kube.KindPod,
		kube.KindDeployment,
		kube.KindDaemonSet,
		kube.KindStatefulSet,
		kube.KindReplicaSet,
		kube.KindReplicationController,
		kube.KindCronJob,
		kube.KindJob:
		return vulnerabilitiesTabPrinter(request, object)
	case kube.KindNode:
		return printKubernetesBenchmarkTab(request, object)
	default:
		return plugin.TabResponse{}, fmt.Errorf("unrecognized workload kind: %s", object.Kind)
	}
}

// SecondaryResourceTabPrinter is called when Octant want to add new tab for the underlying resource.
// For built-in K8s workloads the second tab renders the v1alpha1.ConfigAuditReport.
func SecondaryResourceTabPrinter(request *service.PrintRequest) (plugin.TabResponse, error) {
	if request.Object == nil {
		return plugin.TabResponse{}, errors.New("request object is nil")
	}

	workload, err := getWorkloadFromObject(request.Object)
	if err != nil {
		return plugin.TabResponse{}, err
	}

	switch workload.Kind {
	case kube.KindPod,
		kube.KindDeployment,
		kube.KindDaemonSet,
		kube.KindStatefulSet,
		kube.KindReplicaSet,
		kube.KindReplicationController,
		kube.KindCronJob,
		kube.KindJob:
		return configAuditTabPrinter(request, workload)
	default:
		//return plugin.TabResponse{}, fmt.Errorf("unrecognized workload kind: %s", workload.Kind)
		return plugin.TabResponse{}, nil
	}

}

func vulnerabilitiesTabPrinter(request *service.PrintRequest, workload kube.Object) (plugin.TabResponse, error) {
	repository := model.NewRepository(request.DashboardClient)

	_, err := repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.VulnerabilityReportsCRName)
	vulnerabilityReportsDefined := err == nil

	var reports []model.NamedVulnerabilityReport
	if vulnerabilityReportsDefined {
		reports, err = repository.GetVulnerabilityReportsByOwner(request.Context(), workload)
		if err != nil {
			return plugin.TabResponse{}, err
		}
	}

	tab := component.NewTabWithContents(vulnerabilities.NewReport(workload, vulnerabilityReportsDefined, reports))
	return plugin.TabResponse{Tab: tab}, nil
}

// printKubernetesBenchmarkTab creates the CIS Kubernetes Benchmark TabResponse
// for the specified node.
func printKubernetesBenchmarkTab(request *service.PrintRequest, node kube.Object) (plugin.TabResponse, error) {
	repository := model.NewRepository(request.DashboardClient)

	_, err := repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.CISKubeBenchReportCRName)
	kubeBenchReportDefined := err == nil

	var report *v1alpha1.CISKubeBenchReport

	if kubeBenchReportDefined {
		report, err = repository.GetCISKubeBenchReport(request.Context(), node.Name)
		if err != nil {
			return plugin.TabResponse{}, nil
		}
	}

	return plugin.TabResponse{
		Tab: component.NewTabWithContents(kubebench.NewReport(kubeBenchReportDefined, report)),
	}, nil
}

func configAuditTabPrinter(request *service.PrintRequest, workload kube.Object) (plugin.TabResponse, error) {
	repository := model.NewRepository(request.DashboardClient)
	report, err := repository.GetConfigAuditReportByOwner(request.Context(), workload)
	if err != nil {
		return plugin.TabResponse{}, err
	}
	return plugin.TabResponse{Tab: component.NewTabWithContents(configaudit.NewReport(workload, true, report))}, nil
}

// ResourcePrinter is called when Octant wants to print the details of the underlying resource.
func ResourcePrinter(request *service.PrintRequest) (plugin.PrintResponse, error) {
	if request.Object == nil {
		return plugin.PrintResponse{}, errors.New("object is nil")
	}

	workload, err := getWorkloadFromObject(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	repository := model.NewRepository(request.DashboardClient)

	_, err = repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.VulnerabilityReportsCRName)
	vulnerabilityReportsDefined := err == nil

	var summary *v1alpha1.VulnerabilitySummary
	if vulnerabilityReportsDefined {
		summary, err = repository.GetVulnerabilitiesSummary(request.Context(), workload)
		if err != nil {
			return plugin.PrintResponse{}, err
		}
	}

	_, err = repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.ConfigAuditReportCRName)
	configAuditReportsDefined := err == nil

	var configAuditReport *v1alpha1.ConfigAuditReport
	var configAuditSummary *v1alpha1.ConfigAuditSummary
	if configAuditReportsDefined {
		configAuditReport, err = repository.GetConfigAuditReportByOwner(request.Context(), workload)
		if err != nil {
			return plugin.PrintResponse{}, err
		}
		if configAuditReport != nil {
			configAuditSummary = &configAuditReport.Report.Summary
		}
	}

	return plugin.PrintResponse{
		Status: vulnerabilities.NewSummarySections(summary),
		Config: configaudit.NewSummarySections(configAuditSummary),
	}, nil
}

func getWorkloadFromObject(o runtime.Object) (workload kube.Object, err error) {
	accessor := meta.NewAccessor()

	kind, err := accessor.Kind(o)
	if err != nil {
		return
	}

	name, err := accessor.Name(o)
	if err != nil {
		return
	}

	namespace, err := accessor.Namespace(o)
	if err != nil {
		return
	}

	workload = kube.Object{
		Kind:      kube.Kind(kind),
		Name:      name,
		Namespace: namespace,
	}
	return
}
