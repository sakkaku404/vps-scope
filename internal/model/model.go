package model

import "time"

type Status string

const (
	Pass    Status = "PASS"
	Risk    Status = "RISK"
	Info    Status = "INFO"
	Unknown Status = "UNKNOWN"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

type Evidence struct {
	Source string `json:"source"`
	Key    string `json:"key,omitempty"`
	Value  string `json:"value"`
}

type Finding struct {
	ID            string            `json:"id"`
	ReasonCode    string            `json:"reason_code,omitempty"`
	Category      string            `json:"category"`
	Status        Status            `json:"status"`
	Severity      Severity          `json:"severity,omitempty"`
	Evidence      []Evidence        `json:"evidence,omitempty"`
	Facts         map[string]string `json:"facts,omitempty"`
	Unavailable   bool              `json:"unavailable,omitempty"`
	NotApplicable bool              `json:"not_applicable,omitempty"`
	Error         string            `json:"error,omitempty"`
}

type Host struct {
	StableID       string `json:"stable_id"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	Kernel         string `json:"kernel"`
	Architecture   string `json:"architecture"`
	Virtualization string `json:"virtualization,omitempty"`
	IsRoot         bool   `json:"is_root"`
}

type Profile struct {
	Requested string   `json:"requested"`
	Detected  string   `json:"detected"`
	Effective string   `json:"effective"`
	Reasons   []string `json:"reasons,omitempty"`
}

type Summary struct {
	Pass          int `json:"pass"`
	Risk          int `json:"risk"`
	Info          int `json:"info"`
	Unknown       int `json:"unknown"`
	Completed     int `json:"completed"`
	Unavailable   int `json:"unavailable"`
	NotApplicable int `json:"not_applicable"`
}

type Report struct {
	SchemaVersion string            `json:"schema_version"`
	ToolVersion   string            `json:"tool_version"`
	ToolCommit    string            `json:"tool_commit"`
	Locale        string            `json:"locale"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	LogSince      string            `json:"log_since"`
	Host          Host              `json:"host"`
	Profile       Profile           `json:"profile"`
	Summary       Summary           `json:"summary"`
	Findings      []Finding         `json:"findings"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

func (r *Report) Recount() {
	r.Summary = Summary{}
	for _, f := range r.Findings {
		if f.NotApplicable {
			r.Summary.NotApplicable++
			continue
		}
		if f.Unavailable {
			r.Summary.Unavailable++
		}
		switch f.Status {
		case Pass:
			r.Summary.Pass++
		case Risk:
			r.Summary.Risk++
		case Info:
			r.Summary.Info++
		case Unknown:
			r.Summary.Unknown++
		}
		r.Summary.Completed++
	}
}
