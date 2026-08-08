package contract

// Report resource limits are part of the schema-1.0 safety contract. The Go
// semantic validator, report normalizer, topology builder, and published JSON
// Schema are required to agree on these values.
const (
	MaxReportFindings        = 1024
	MaxReportEndpoints       = 4096
	MaxReportMetadataEntries = 256
	MaxReportProfileReasons  = 64

	MaxDeploymentComponents = 512
	MaxDeploymentEndpoints  = 2048
	MaxDeploymentLinks      = 8192

	MaxFindingEvidenceEntries = 256
	MaxFindingFactEntries     = 256
	MaxEvidenceSourceBytes    = 256
	MaxEvidenceKeyBytes       = 128
	MaxEvidenceValueBytes     = 8 << 10
	MaxFindingErrorBytes      = 2 << 10
	MaxFindingFactKeyBytes    = 128
	MaxFindingFactValueBytes  = 8 << 10
)
