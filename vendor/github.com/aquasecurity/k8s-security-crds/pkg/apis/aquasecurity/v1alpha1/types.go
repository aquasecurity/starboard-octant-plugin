package v1alpha1

import (
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

type VulnerabilitySummary struct {
	CriticalCount int `json:"criticalCount"`
	HighCount     int `json:"highCount"`
	MediumCount   int `json:"mediumCount"`
	LowCount      int `json:"lowCount"`
	UnknownCount  int `json:"unknownCount"`
}

// VulnerabilityItem is the spec for a vulnerability record.
type VulnerabilityItem struct {
	VulnerabilityID  string   `json:"vulnerabilityID"`
	Resource         string   `json:"resource"`
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion"`
	Severity         Severity `json:"severity"`
	LayerID          string   `json:"layerID"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Links            []string `json:"links"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Vulnerability is a specification for the Vulnerability resource.
type Vulnerability struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata,omitempty"`

	Spec VulnerabilityReport `json:"spec"`
}

// VulnerabilityReport is the spec for the vulnerability report.
type VulnerabilityReport struct {
	Summary         VulnerabilitySummary `json:"summary"`
	Vulnerabilities []VulnerabilityItem  `json:"vulnerabilities"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VulnerabilityList is a list of Vulnerability resources.
type VulnerabilityList struct {
	meta.TypeMeta `json:",inline"`
	meta.ListMeta `json:"metadata"`

	Items []Vulnerability `json:"items"`
}
