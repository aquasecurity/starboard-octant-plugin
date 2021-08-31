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
		expectedTextComponent *component.Text
	}{
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  true,
				Severity: "warning",
			},
			expectedTextComponent: component.NewText("check-id", func(t *component.Text) {
				t.SetStatus(component.TextStatusOK)
			}),
		},
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  false,
				Severity: "warning",
			},
			expectedTextComponent: component.NewText("check-id", func(t *component.Text) {
				t.SetStatus(component.TextStatusWarning)
			}),
		},
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  true,
				Severity: "danger",
			},
			expectedTextComponent: component.NewText("check-id", func(t *component.Text) {
				t.SetStatus(component.TextStatusOK)
			}),
		},
		{
			check: v1alpha1.Check{
				ID:       "check-id",
				Success:  false,
				Severity: "danger",
			},
			expectedTextComponent: component.NewText("check-id", func(t *component.Text) {
				t.SetStatus(component.TextStatusError)
			}),
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Should return text component for severity %s and success status %t", tc.check.Severity, tc.check.Success), func(t *testing.T) {
			c, ok := configaudit.CheckIDWithIcon(tc.check).(*component.Text)
			assert.True(t, ok)
			assert.Equal(t, tc.expectedTextComponent, c)
		})
	}
}
