package configaudit_test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/configaudit"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func TestCheckIDWithIcon(t *testing.T) {
	testCases := []struct {
		check                v1alpha1.Check
		expectedMarkdownText string
	}{
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  true,
				Severity: "warning",
			},
			expectedMarkdownText: `<clr-icon shape="check-circle" class="is-solid is-success"></clr-icon>&nbsp;check-id`,
		},
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  false,
				Severity: "warning",
			},
			expectedMarkdownText: `<clr-icon shape="info-circle" class="is-solid is-warning"></clr-icon>&nbsp;check-id`,
		},
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  true,
				Severity: "danger",
			},
			expectedMarkdownText: `<clr-icon shape="check-circle" class="is-solid is-success"></clr-icon>&nbsp;check-id`,
		},
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  false,
				Severity: "danger",
			},
			expectedMarkdownText: `<clr-icon shape="exclamation-circle" class="is-solid is-danger"></clr-icon>&nbsp;check-id`,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Should return markdown text component for severity %s and success status %t", tc.check.Severity, tc.check.Success), func(t *testing.T) {
			c, ok := configaudit.CheckIDWithIcon(tc.check).(*component.Text)
			assert.True(t, ok)
			assert.True(t, c.TrustedContent())
			assert.Equal(t, tc.expectedMarkdownText, c.Config.Text)
		})
	}
}
