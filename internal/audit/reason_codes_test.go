package audit

import (
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestReasonCodeContract(t *testing.T) {
	tests := []struct {
		name string
		in   model.Finding
		want string
	}{
		{"pass", model.Finding{ID: "SSH-001", Status: model.Pass}, "ssh.001.verified"},
		{"not applicable", model.Finding{ID: "DOCKER-001", Status: model.Info, NotApplicable: true}, "docker.001.not-applicable"},
		{"unavailable", model.Finding{ID: "TLS-002", Status: model.Unknown, Unavailable: true}, "tls.002.evidence-unavailable"},
		{"unsupported panel schema", model.Finding{ID: "WORK-002", Status: model.Unknown, Facts: map[string]string{"unsupported_panel_schemas": "1"}}, "work.002.unsupported-panel-schema"},
		{"public plaintext panel", model.Finding{ID: "WORK-002", Status: model.Risk, Facts: map[string]string{"public_plaintext_management": "1"}}, "work.002.public-plaintext-management"},
		{"expired certificate", model.Finding{ID: "TLS-001", Status: model.Risk, Facts: map[string]string{"minimum_certificate_days": "-2"}}, "tls.001.certificate-expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reasonCode(tt.in); got != tt.want {
				t.Fatalf("reasonCode()=%q want %q", got, tt.want)
			}
		})
	}
}
