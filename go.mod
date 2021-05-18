module github.com/aquasecurity/starboard-octant-plugin

go 1.16

require (
	github.com/aquasecurity/starboard v0.10.3
	github.com/stretchr/testify v1.7.0
	github.com/vmware-tanzu/octant v0.20.0
	k8s.io/api v0.19.3
	k8s.io/apiextensions-apiserver v0.19.3
	k8s.io/apimachinery v0.19.3
)

replace (
	k8s.io/api => k8s.io/api v0.19.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.3
	k8s.io/client-go => k8s.io/client-go v0.19.3
)
