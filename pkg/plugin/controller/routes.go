package controller

import (
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
)

func InitRoutes(router *service.Router) {
	router.HandleFunc("", rootHandler)
}
