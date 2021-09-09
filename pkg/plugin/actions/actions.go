package actions

import (
	"context"
	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kubehunter"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/vmware-tanzu/octant/pkg/action"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"time"
)

const (
	StarboardKubeHunterScan = "starboard.octant.dev/scanKubeHunter"

	kubeHunterReportName = "cluster"
)

func ActionHandler(request *service.ActionRequest) error {
	actionName, err := request.Payload.String("action")
	if err != nil {
		return err
	}

	switch actionName {
	case StarboardKubeHunterScan:
		alert := action.CreateAlert(action.AlertTypeInfo, "Creating kube-hunter report...", time.Second * 15)
		request.DashboardClient.SendAlert(request.Context(), request.ClientState.ClientID(), alert)
		return startKubeHunterScan(request.Context())
	default:
		// no-op
	}
	return nil
}

func startKubeHunterScan(ctx context.Context) error {
	configFlags := genericclioptions.NewConfigFlags(true)
	restconfig, err := configFlags.ToRESTConfig()
	if err != nil {
		return err
	}
	kubeClientset, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		return err
	}
	opts := kube.ScannerOpts{ScanJobTimeout: time.Minute}
	config, err := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName).Read(ctx)
	if err != nil {
		return err
	}
	scanner := kubehunter.NewScanner(starboard.NewScheme(), kubeClientset, config, opts)
	report, err := scanner.Scan(ctx)
	if err != nil {
		return err
	}
	starboardClientset, err := versioned.NewForConfig(restconfig)
	if err != nil {
		return err
	}
	return kubehunter.NewWriter(starboardClientset).Write(ctx, report, kubeHunterReportName)
}
