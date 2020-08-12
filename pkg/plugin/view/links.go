package view

import (
	"fmt"
)

func ToMarkdownLink(title, url string) string {
	return fmt.Sprintf("[%s](%s)", title, url)
}
