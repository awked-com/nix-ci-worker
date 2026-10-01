package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

const retentionAnnotation = "com.awked.infra-ci.retention.v1"

// Keep source selections, store paths, commands, and credentials in the catalog.
type retentionRecord struct {
	Kind        string `json:"kind"`
	Run         string `json:"run"`
	System      string `json:"system,omitempty"`
	Attempt     int    `json:"attempt,omitempty"`
	Publication int    `json:"publication,omitempty"`
}

func snapshotRetention(metadata map[string]any) retentionRecord {
	record := retentionRecord{Kind: String(metadata["kind"]), Run: valueID(metadata["run"])}
	if record.Kind == "live" {
		record.System = String(metadata["system"])
		record.Attempt = Int(metadata["attempt"])
		record.Publication = Int(metadata["publication"])
	}
	return record
}

func validRetentionRun(id string) bool {
	number, err := strconv.ParseUint(id, 10, 64)
	return err == nil && number > 0
}

func (r retentionRecord) validate() error {
	if r.Kind != "pool" && r.Kind != "live" {
		return errors.New("invalid retention artifact kind")
	}
	if !validRetentionRun(r.Run) {
		return errors.New("missing or invalid retention run ID")
	}
	if r.Kind == "live" {
		if _, ok := Systems[r.System]; !ok {
			return errors.New("invalid retention platform")
		}
		if r.Attempt < 1 || r.Publication < 1 {
			return errors.New("invalid retention generation")
		}
	} else if r.System != "" || r.Attempt != 0 || r.Publication != 0 {
		return errors.New("unexpected retention platform")
	}
	return nil
}

func valueID(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}
