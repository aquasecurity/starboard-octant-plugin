package model

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
	appsv1 "k8s.io/api/apps/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	ClusterKind = "Cluster"
)

// Repository defines methods for accessing Kubernetes object.
type Repository struct {
	client service.Dashboard
}

// NewRepository constructs new Kubernetes objects repository
// with the specified Kubernetes client provided by Octant extensions API.
func NewRepository(client service.Dashboard) *Repository {
	return &Repository{
		client: client,
	}
}

// NamedVulnerabilityReport allows sorting VulnerabilityReports by container name.
type NamedVulnerabilityReport struct {
	Name   string
	Report v1alpha1.VulnerabilityReport
}

func (r *Repository) GetVulnerabilitiesSummary(ctx context.Context, options kube.Object) (*v1alpha1.VulnerabilitySummary, error) {
	vs := &v1alpha1.VulnerabilitySummary{}
	containerReports, err := r.GetVulnerabilityReportsByOwner(ctx, options)
	if err != nil {
		return nil, err
	}
	for _, cr := range containerReports {
		for _, v := range cr.Report.Report.Vulnerabilities {
			switch v.Severity {
			case v1alpha1.SeverityCritical:
				vs.CriticalCount++
			case v1alpha1.SeverityHigh:
				vs.HighCount++
			case v1alpha1.SeverityMedium:
				vs.MediumCount++
			case v1alpha1.SeverityLow:
				vs.LowCount++
			default:
				vs.UnknownCount++
			}
		}
	}
	return vs, nil
}

func (r *Repository) GetCustomResourceDefinitionByName(ctx context.Context, name string) (*apiextensionsv1.CustomResourceDefinition, error) {
	unstructuredResp, err := r.client.Get(ctx, store.Key{
		APIVersion: "apiextensions.k8s.io/v1beta1",
		Kind:       "CustomResourceDefinition",
		Name:       name,
	})
	if err != nil {
		return nil, err
	}
	var crd apiextensionsv1.CustomResourceDefinition
	err = r.structure(unstructuredResp, &crd)
	return &crd, err
}

// GetControllerOf returns the controller Object for the specified controlee Object.
// Returns nil if there's no such controller.
func (r *Repository) GetControllerOf(ctx context.Context, controlee kube.Object) (*kube.Object, error) {
	var obj metav1.PartialObjectMetadata

	unstructuredObj, err := r.client.Get(ctx, store.Key{
		Kind:      string(controlee.Kind),
		Name:      controlee.Name,
		Namespace: controlee.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("getting controlee: %w", err)
	}

	err = r.structure(unstructuredObj, &obj)
	if err != nil {
		return nil, fmt.Errorf("structuring controlee: %w", err)
	}

	controllerRef := metav1.GetControllerOf(&obj)
	if controllerRef == nil {
		return nil, nil
	}

	return &kube.Object{
		Kind:      kube.Kind(controllerRef.Kind),
		Name:      controllerRef.Name,
		Namespace: controlee.Namespace,
	}, nil
}

// GetReplicaSetForDeployment returns the active ReplicaSet Object for
// the specified Deployment Object.
func (r *Repository) GetReplicaSetForDeployment(ctx context.Context, object kube.Object) (*kube.Object, error) {
	var deployment appsv1.Deployment
	unstructuredDeployment, err := r.client.Get(ctx, store.Key{
		APIVersion: "apps/v1",
		Kind:       string(object.Kind),
		Name:       object.Name,
		Namespace:  object.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("getting deployment: %w", err)
	}

	err = r.structure(unstructuredDeployment, &deployment)
	if err != nil {
		return nil, fmt.Errorf("structuring deployment: %w", err)
	}

	deploymentSelector, err := metav1.LabelSelectorAsMap(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("mapping label selector: %w", err)
	}
	selector := labels.Set(deploymentSelector)

	var replicaSetList appsv1.ReplicaSetList
	unstructuredReplicaSetList, err := r.client.List(ctx, store.Key{
		APIVersion: "apps/v1",
		Kind:       string(kube.KindReplicaSet),
		Namespace:  object.Namespace,
		Selector:   &selector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing replicasets: %w", err)
	}
	err = r.structure(unstructuredReplicaSetList, &replicaSetList)
	if err != nil {
		return nil, fmt.Errorf("structuring replicaset list: %w", err)
	}

	for _, replicaSet := range replicaSetList.Items {
		if deployment.Annotations["deployment.kubernetes.io/revision"] !=
			replicaSet.Annotations["deployment.kubernetes.io/revision"] {
			continue
		}
		return &kube.Object{Kind: kube.KindReplicaSet,
			Name:      replicaSet.Name,
			Namespace: replicaSet.Namespace}, nil
	}
	return nil, nil
}

// GetVulnerabilityReportsByOwner returns VulnerabilityReports owned by
// the specified Kubernetes object. The reports are named after container
// names so we can sort them and render in predictable order.
//
// Note: If there are no VulnerabilityReports which are owned by the
// specified Deployment, this method does an extra attempt to lookup
// the VulnerabilityReports owned by its active ReplicaSet.
// Similarly if there are no VulnerabilityReports owned by the specified
// Pod it will lookup VulnerabilityReports owned by the Pod's controller.
func (r *Repository) GetVulnerabilityReportsByOwner(ctx context.Context, owner kube.Object) ([]NamedVulnerabilityReport, error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, v1alpha1.VulnerabilityReportsCRVersion),
		Kind:       v1alpha1.VulnerabilityReportKind,
		Namespace:  owner.Namespace,
		Selector: &labels.Set{
			starboard.LabelResourceKind:      string(owner.Kind),
			starboard.LabelResourceName:      owner.Name,
			starboard.LabelResourceNamespace: owner.Namespace,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("listing vulnerabilityreports: %w", err)
	}

	var reportList v1alpha1.VulnerabilityReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		return nil, fmt.Errorf("structuring VulnerabilityReportList: %w", err)
	}

	// Even if there are no VulnerabilityReports directly owned by the given Deployment
	// we are trying to get VulnerabilityReports owned by the active ReplicaSet.
	if len(reportList.Items) == 0 && owner.Kind == kube.KindDeployment {
		replicaSet, err := r.GetReplicaSetForDeployment(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("getting replicaset for deployment: %w", err)
		}
		if replicaSet == nil {
			return []NamedVulnerabilityReport{}, nil
		}
		return r.GetVulnerabilityReportsByOwner(ctx, *replicaSet)
	}

	// If there are no VulnerabilityReports owned by the given Pod
	// we are trying to get VulnerabilityReports owned by its controller.
	if len(reportList.Items) == 0 && owner.Kind == kube.KindPod {
		controller, err := r.GetControllerOf(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("getting replicaset for pod: %w", err)
		}
		if controller == nil {
			return []NamedVulnerabilityReport{}, nil
		}
		return r.GetVulnerabilityReportsByOwner(ctx, *controller)
	}

	var reports []NamedVulnerabilityReport

	for _, item := range reportList.Items {
		if containerName, containerNameSpecified := item.Labels[starboard.LabelContainerName]; containerNameSpecified {
			reports = append(reports, NamedVulnerabilityReport{
				Name:   containerName,
				Report: *item.DeepCopy(),
			})
		}
	}

	sort.SliceStable(reports, func(i, j int) bool {
		return strings.Compare(reports[i].Name, reports[j].Name) < 0
	})

	return reports, nil
}

func (r *Repository) GetConfigAuditReportByOwner(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, v1alpha1.ConfigAuditReportCRVersion),
		Kind:       v1alpha1.ConfigAuditReportKind,
		Namespace:  owner.Namespace,
		Selector: &labels.Set{
			starboard.LabelResourceKind:      string(owner.Kind),
			starboard.LabelResourceName:      owner.Name,
			starboard.LabelResourceNamespace: owner.Namespace,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("listing configauditreports: %w", err)
	}

	// Even if there is no ConfigAuditReport directly owned by the given Deployment
	// we are trying to get the ConfigAuditReport owned by the active ReplicaSet.
	if len(unstructuredList.Items) == 0 && owner.Kind == kube.KindDeployment {
		replicaSet, err := r.GetReplicaSetForDeployment(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("getting replicaset for deployment: %w", err)
		}
		if replicaSet == nil {
			return nil, nil
		}
		return r.GetConfigAuditReportByOwner(ctx, *replicaSet)
	}

	// If there is no ConfigAuditReport owned by the given Pod
	// we are trying to get the ConfigAuditReport owned by its controller.
	if len(unstructuredList.Items) == 0 && owner.Kind == kube.KindPod {
		controller, err := r.GetControllerOf(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("getting replicaset for pod: %w", err)
		}
		if controller == nil {
			return nil, nil
		}
		return r.GetConfigAuditReportByOwner(ctx, *controller)
	}

	if len(unstructuredList.Items) == 0 {
		return nil, nil
	}
	var reportList v1alpha1.ConfigAuditReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling JSON to ConfigAuditReportList: %w", err)
	}

	return reportList.Items[0].DeepCopy(), nil
}

func (r *Repository) GetCISKubeBenchReport(ctx context.Context, node string) (report *v1alpha1.CISKubeBenchReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, v1alpha1.CISKubeBenchReportCRVersion),
		Kind:       v1alpha1.CISKubeBenchReportKind,
		Selector: &labels.Set{
			starboard.LabelResourceKind: string(kube.KindNode),
			starboard.LabelResourceName: node,
		},
	})
	if err != nil {
		err = fmt.Errorf("listing CIS Kubernetes Benchmarks: %w", err)
		return
	}
	if len(unstructuredList.Items) == 0 {
		return
	}
	var reportList v1alpha1.CISKubeBenchReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		err = fmt.Errorf("unmarshalling JSON to CISKubernetesBenchmarkList: %w", err)
		return
	}

	report = reportList.Items[0].DeepCopy()
	return
}

func (r *Repository) GetKubeHunterReport(ctx context.Context) (report *v1alpha1.KubeHunterReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, v1alpha1.KubeHunterReportCRVersion),
		Kind:       v1alpha1.KubeHunterReportKind,
		Selector: &labels.Set{
			starboard.LabelResourceKind: ClusterKind,
			starboard.LabelResourceName: "cluster",
		},
	})
	if err != nil {
		return
	}
	if len(unstructuredList.Items) == 0 {
		return
	}
	var reportList v1alpha1.KubeHunterReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		return
	}

	report = reportList.Items[0].DeepCopy()
	return
}

func (r *Repository) structure(m json.Marshaler, v interface{}) (err error) {
	b, err := m.MarshalJSON()
	if err != nil {
		return
	}
	err = json.Unmarshal(b, v)
	return
}
