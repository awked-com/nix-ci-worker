package worker

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildRequestSelectsTargets(t *testing.T) {
	id, source := strings.Repeat("a", 32), "feature/ci"
	for _, test := range []struct {
		name, host, pkg string
		selection       map[string]string
	}{
		{"all", "", "", nil},
		{"system", "oci1", "", map[string]string{"host": "oci1"}},
		{"package", "oci1", "linuxPackages.kernel", map[string]string{"host": "oci1", "package": "linuxPackages.kernel"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewBuildRequest(id, source, test.host, test.pkg)
			if err != nil || request.ID != id || request.Source != source || !reflect.DeepEqual(request.Selection, test.selection) {
				t.Fatal(request, err)
			}
		})
	}
}

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
