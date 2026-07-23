package app

import (
	"fmt"
	"os"

	"github.com/sakkaku404/vps-scope/internal/audit"
)

func (e environment) policy(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: vps-scope policy init FILE.json | vps-scope policy validate FILE.json")
	}
	switch args[0] {
	case "init":
		if err := audit.WritePolicyTemplate(args[1]); err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("refusing to overwrite existing policy %q", args[1])
			}
			return err
		}
		fmt.Fprintf(e.out, "policy template written: %s\n", args[1])
		return nil
	case "validate":
		policy, err := audit.LoadPolicy(args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "PASS policy schema=%s endpoints=%d\n", policy.SchemaVersion, len(policy.Endpoints))
		return nil
	default:
		return fmt.Errorf("unknown policy command %q; use init or validate", args[0])
	}
}
