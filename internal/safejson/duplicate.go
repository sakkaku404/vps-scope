// Package safejson contains strict JSON checks shared by every untrusted
// machine-readable input. The standard library accepts duplicate object names
// with last-value-wins semantics, which is unsafe for signed, reviewed, or
// policy-bearing documents.
package safejson

import (
	"encoding/json"
	"errors"
	"io"
)

const maxJSONNesting = 256

// RejectDuplicateMembers validates one complete JSON value and rejects a
// duplicate object member at any nesting depth. Member names are intentionally
// omitted from errors because untrusted names can contain secrets or terminal
// control bytes.
func RejectDuplicateMembers(r io.Reader) error {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > maxJSONNesting {
			return errors.New("JSON nesting exceeds safety limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				member, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := member.(string)
				if !ok {
					return errors.New("invalid JSON object member")
				}
				if seen[name] {
					return errors.New("duplicate JSON object member")
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim('}') {
				return errors.New("invalid JSON object terminator")
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim(']') {
				return errors.New("invalid JSON array terminator")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after JSON document")
		}
		return err
	}
	return nil
}
