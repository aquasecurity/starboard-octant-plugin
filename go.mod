module github.com/aquasecurity/starboard-octant-plugin

go 1.15

require (
	github.com/aquasecurity/starboard v0.5.0
	github.com/stretchr/testify v1.6.1
	github.com/vmware-tanzu/octant v0.15.0
	k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver v0.19.2
	k8s.io/apimachinery v0.19.2
)

replace (
	k8s.io/api => k8s.io/api v0.19.0-alpha.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.0-alpha.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0-beta.2
	k8s.io/client-go => k8s.io/client-go v0.19.0-alpha.3
)
