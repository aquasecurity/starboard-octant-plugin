package view

import (
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewDebug(s string) component.Component {
	card := component.NewCard([]component.TitleComponent{component.NewText("Debug")})
	card.SetBody(component.NewMarkdownText(s))
	return card
}
