package settings

import (
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	nodeGVK                  = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}
	podGVK                   = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	deploymentGVK            = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	daemonSetGVK             = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}
	statefulSetGVK           = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}
	replicaSetGVK            = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"}
	replicationControllerGVK = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ReplicationController"}
	cronJobGVK               = schema.GroupVersionKind{Group: "batch", Version: "v1beta1", Kind: "CronJob"}
	jobGVK                   = schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}
)

func GetCapabilities() *plugin.Capabilities {
	return &plugin.Capabilities{
		SupportsTab: []schema.GroupVersionKind{
			podGVK,
			deploymentGVK,
			daemonSetGVK,
			statefulSetGVK,
			replicaSetGVK,
			replicationControllerGVK,
			cronJobGVK,
			jobGVK,
			nodeGVK,
		},
		SupportsPrinterConfig: []schema.GroupVersionKind{
			podGVK,
			deploymentGVK,
			daemonSetGVK,
			statefulSetGVK,
			replicaSetGVK,
			replicationControllerGVK,
			cronJobGVK,
			jobGVK,
		},
		IsModule: true,
	}
}
