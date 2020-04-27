package settings

import (
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	nodeGVK        = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}
	podGVK         = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	deploymentGVK  = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	daemonSetGVK   = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}
	statefulSetGVK = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}
	namespaceGVK   = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}
)

func GetCapabilities() *plugin.Capabilities {
	return &plugin.Capabilities{
		SupportsTab: []schema.GroupVersionKind{
			podGVK,
			deploymentGVK,
			daemonSetGVK,
			statefulSetGVK,
			namespaceGVK,
			nodeGVK,
		},
		SupportsPrinterConfig: []schema.GroupVersionKind{
			podGVK,
			deploymentGVK,
			daemonSetGVK,
			statefulSetGVK,
		},
		IsModule: true,
	}
}
