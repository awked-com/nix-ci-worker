package worker

import (
	"strings"
	"testing"
)

func TestBuildRequestRejectsInvalidInputs(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, test := range []struct {
		name, id, source, host, pkg string
	}{
		{"missing ID", "", "main", "", ""},
		{"invalid ID", "invalid", "main", "", ""},
		{"missing source", id, "", "", ""},
		{"package without host", id, "main", "", "hello"},
		{"invalid host", id, "main", "../oci1", ""},
		{"invalid package", id, "main", "oci1", "hello;bad"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewBuildRequest(test.id, test.source, test.host, test.pkg); err == nil {
				t.Fatal("invalid inputs accepted")
			}
		})
	}
}
