module github.com/aquasecurity/starboard-octant-plugin

go 1.15

require (
	github.com/aquasecurity/starboard v0.9.2
	github.com/elazarl/goproxy/ext v0.0.0-20210110162100-a92cc753f88e // indirect
	github.com/stretchr/testify v1.7.0
	github.com/vmware-tanzu/octant v0.18.0
	k8s.io/api v0.19.3
	k8s.io/apiextensions-apiserver v0.19.3
	k8s.io/apimachinery v0.19.3
)

replace (
	k8s.io/api => k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.2
	k8s.io/client-go => k8s.io/client-go v0.19.2
)
