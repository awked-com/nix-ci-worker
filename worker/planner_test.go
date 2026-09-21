package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type covered map[string]bool

func (c covered) Contains(path string) bool { return c[path] }

func derivation(out string, deps ...string) Derivation {
	d := Derivation{
		InputDrvs: map[string]derivationInput{},
		Outputs:   map[string]derivationOutput{"out": {Path: out}},
	}
	for _, dep := range deps {
		d.InputDrvs[dep] = derivationInput{Outputs: []string{"out"}}
	}

	return d
}

func TestBuildInputsSelectOnlyNeededDependencyOutputs(t *testing.T) {
	path := func(name string) string { return "/nix/store/00000000000000000000000000000000-" + name }
	root, dep, compiler := path("root.drv"), path("dep.drv"), path("compiler.drv")
	d := derivation(path("root"), dep)
	d.InputSrcs = []string{path("source")}
	d.InputDrvs[dep] = derivationInput{Outputs: []string{"dev"}}
	library := derivation(path("dep"), compiler)
	library.Outputs["dev"] = derivationOutput{Path: path("dep-dev")}
	p, err := NewPlan(map[string]string{"root": root}, map[string]Derivation{
		root: d, dep: library, compiler: derivation(path("compiler")),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.BuildInputs(root)
	want := []string{path("dep-dev"), root, path("source")}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("build inputs include unused outputs or omit required inputs", got, err)
	}
	for _, input := range []derivationInput{
		{},
		{Outputs: []string{"missing"}},
		{Outputs: []string{"out"}, DynamicOutputs: map[string]json.RawMessage{"out": json.RawMessage(`{}`)}},
	} {
		d.InputDrvs[dep] = input
		if _, err := p.BuildInputs(root); err == nil {
			t.Fatal("invalid dependency accepted", input)
		}
	}
	d.InputDrvs[dep] = derivationInput{Outputs: []string{"out"}}
	p.Outputs[dep]["out"] = ""
	if _, err := p.BuildInputs(root); err == nil {
		t.Fatal("unresolved dependency accepted")
	}
}

func TestPlanRequiresRecipesSourcesAndAllOutputs(t *testing.T) {
	root := "/nix/store/root.drv"
	dep := "/nix/store/dependency.drv"
	d := derivation("/nix/store/root", dep)
	d.InputSrcs = []string{"/nix/store/source"}
	d.Outputs["dev"] = derivationOutput{Path: "/nix/store/root-dev"}
	p, e := NewPlan(map[string]string{"root": root}, map[string]Derivation{
		root: d,
		dep:  derivation("/nix/store/dependency"),
	}, []string{"/nix/store/extra"})
	if e != nil {
		t.Fatal(e)
	}

	all := covered{}
	for path := range p.Required {
		all[path] = true
	}

	if !p.Complete(all) {
		t.Fatal("complete plan rejected")
	}

	for path := range p.Required {
		delete(all, path)
		if p.Complete(all) {
			t.Fatalf("missing %s accepted", path)
		}

		all[path] = true
	}

	delete(all, "/nix/store/root-dev")
	if got := p.Missing(all, map[string]bool{}); !reflect.DeepEqual(got, []string{root + "^dev"}) {
		t.Fatalf("missing %v", got)
	}

	if got := p.Missing(all, map[string]bool{"/nix/store/root-dev": true}); len(got) != 0 {
		t.Fatal(got)
	}

	results := p.Results(all, "x86_64-linux")
	if results[0]["status"] != "failure" {
		t.Fatal(results)
	}

	paths, unresolved := p.TargetPaths(root)
	if unresolved || !paths["/nix/store/dependency"] || paths["/nix/store/extra"] {
		t.Fatal(paths, unresolved)
	}
}

func TestPlanBatchesRespectDependenciesAndDetectCycles(t *testing.T) {
	a, b, c := "/nix/store/a.drv", "/nix/store/b.drv", "/nix/store/c.drv"
	p, e := NewPlan(map[string]string{"target": c}, map[string]Derivation{
		a: derivation("a"),
		b: derivation("b", a),
		c: derivation("c", b),
	}, nil)
	if e != nil {
		t.Fatal(e)
	}

	batches, e := p.Batches([]string{c + "^out", a + "^out", b + "^out"}, 2)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(batches, [][]string{
		{a + "^out", b + "^out"},
		{c + "^out"},
	}) {
		t.Fatal(batches)
	}

	d := p.Derivations[a]
	d.InputDrvs[c] = derivationInput{}
	p.Derivations[a] = d
	if _, e = p.Batches([]string{a + "^out"}, 32); e == nil {
		t.Fatal("cyclic graph accepted")
	}
}

func TestDynamicAndContentAddressedOutputsNeverPrematurelyComplete(t *testing.T) {
	drv := "/nix/store/target.drv"
	p, e := NewPlan(map[string]string{"target": drv}, map[string]Derivation{drv: derivation("")}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if p.Complete(covered{drv: true}) {
		t.Fatal("unresolved output complete")
	}

	if e = p.Resolve(func(args []string, _ bool, _ []byte) ([]byte, error) {
		return []byte(`[{"outputs":{"out":"/nix/store/resolved"}}]`), nil
	}); e != nil {
		t.Fatal(e)
	}

	if !p.Complete(covered{
		drv:                   true,
		"/nix/store/resolved": true,
	}) {
		t.Fatal("resolved output unavailable")
	}

	d := p.Derivations[drv]
	d.Dynamic = true
	p.Derivations[drv] = d
	if p.Complete(covered{
		drv:                   true,
		"/nix/store/resolved": true,
	}) {
		t.Fatal("dynamic output complete")
	}

	p.Outputs[drv]["out"] = ""
	if e = p.Resolve(func([]string, bool, []byte) ([]byte, error) {
		return []byte(`[{"outputs":{"changed":"/nix/store/result"}}]`), nil
	}); e == nil {
		t.Fatal("changed output inventory accepted")
	}
}

func TestSelectedEvaluationAndPinnedSchema(t *testing.T) {
	source := t.TempDir()
	drv := "/nix/store/" + strings.Repeat("a", 32) + "-selected.drv"
	fixed := "/nix/store/" + strings.Repeat("b", 32) + "-fixed"
	dependency := "/nix/store/" + strings.Repeat("c", 32) + "-dependency"
	input := `{"outputs":["dev"],"dynamicOutputs":{}}`
	calls := 0

	nix := func(args []string, _ bool, data []byte) ([]byte, error) {
		calls++
		switch args[0] {
		case "eval":
			if !strings.HasSuffix(args[3], "#nixosConfigurations.host.pkgs.hello") {
				t.Fatal(args)
			}

			return json.Marshal(map[string]string{
				"system":  "aarch64-linux",
				"drvPath": drv,
			})
		case "derivation":
			if string(data) != drv+"\n" {
				t.Fatal(string(data))
			}

			return []byte(fmt.Sprintf(`{"version": 4, "derivations": {
  %q: {
    "system": "aarch64-linux",
    "inputs": {"drvs": {%q: %s}},
    "outputs": {"out": {"hash": "abc"}},
    "env": {"out": %q, "requiredSystemFeatures": "big-parallel", "preferLocalBuild": "1"}
  },
  %q: {
    "system": "aarch64-linux",
    "outputs": {"dev": {"path": %q}}
  }
}}`, filepath.Base(drv), filepath.Base(dependency)+".drv", input, fixed,
				filepath.Base(dependency)+".drv", filepath.Base(dependency))), nil
		case "path-info":
			return []byte(drv + "\n"), nil
		}

		return nil, errors.New("unexpected nix command")
	}

	selection := map[string]string{
		"host":    "host",
		"package": "hello",
	}
	p, e := Evaluate(source, "x86_64-linux", nix, selection, io.Discard)
	if e == nil || p != nil || calls != 1 {
		t.Fatal(p, e, calls)
	}

	calls = 0
	p, e = Evaluate(source, "aarch64-linux", nix, selection, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	if p.Targets["package-host-hello"] != drv || p.Outputs[drv]["out"] != fixed {
		t.Fatal(p)
	}
	d := p.Derivations[drv]
	if d.System != "aarch64-linux" || d.Env["requiredSystemFeatures"] != "big-parallel" || poolCompatible(d, "aarch64-linux", []string{"big-parallel"}) {
		t.Fatal("decoded derivation lost builder requirements", d)
	}
	if inputs, err := p.BuildInputs(drv); err != nil || !reflect.DeepEqual(inputs, []string{drv, dependency}) {
		t.Fatal("decoded dependency outputs", inputs, err)
	}

	input = `{"outputs":["dev"],"dynamicOutputs":{"out":{}}}`
	p, e = Evaluate(source, "aarch64-linux", nix, selection, io.Discard)
	if e != nil || p.Static() {
		t.Fatal("dynamic input accepted as a static plan", p, e)
	}
}

func TestSelectedEvaluationRejectsUnsupportedNativeTarget(t *testing.T) {
	_, _, e := SelectedTargets(".", map[string]string{"host": "host"}, func([]string, bool, []byte) ([]byte, error) {
		return []byte(`{"system":"x86_64-darwin","drvPath":"/nix/store/test.drv"}`), nil
	})
	if e == nil {
		t.Fatal("unsupported runner accepted")
	}

	for _, selection := range []map[string]string{
		{"host": "../host"},
		{
			"host":    "h",
			"package": "x;touch",
		},
		{
			"host":  "h",
			"other": "x",
		},
	} {
		if e := ValidateSelection(selection); e == nil {
			t.Fatal(selection)
		}
	}
}

func TestNativePlannerNixIntegration(t *testing.T) {
	nativeEnabled(t)

	system, e := NativeSystem()
	if e != nil {
		t.Fatal(e)
	}

	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "tmp")
	if e := os.Symlink(root, alias); e != nil {
		t.Fatal(e)
	}

	root = filepath.Join(alias, "source")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}

	flake := fmt.Sprintf(`{ outputs = { self }: let
  systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
  make = system: derivation {
    name = "infra-ci-native-plan";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" "echo native > $out" ];
  };
  selected = make %q;
in {
  hydraJobs = builtins.listToAttrs (map (system: { name = system; value.simple = make system; }) systems);
  nixosConfigurations.host = {
    config.system.build.toplevel = selected;
    pkgs.hello = selected;
    pkgs.routing = builtins.listToAttrs (map (system: {
      name = system;
      value = { inherit system; drvPath = throw "admission forced the build graph"; };
    }) systems);
  };
}; }`, system)
	if e := os.WriteFile(filepath.Join(root, "flake.nix"), []byte(flake), 0600); e != nil {
		t.Fatal(e)
	}

	var log bytes.Buffer

	nix := func(args []string, capture bool, data []byte) ([]byte, error) {
		return NixRun(root, &log, args, capture, data)
	}

	for name, selection := range map[string]map[string]string{
		"all":  nil,
		"host": {"host": "host"},
		"package": {
			"host":    "host",
			"package": "hello",
		},
	} {
		t.Run(name, func(t *testing.T) {
			log.Reset()
			matrix, e := AdmissionMatrix(root, selection, nix)
			if e != nil {
				t.Fatalf("%v\n%s", e, &log)
			}
			systems, e := matrix.Systems()
			if e != nil || (selection != nil && (len(systems) != 1 || systems[0] != system)) {
				t.Fatal(matrix, e)
			}
			p, e := Evaluate(root, system, nix, selection, &log)
			if e != nil {
				t.Fatalf("%v\n%s", e, &log)
			}
			if p == nil || len(p.Targets) != 1 || len(p.Required) < 2 {
				t.Fatal(p)
			}
		})
	}
	for _, system := range sortedKeys(Systems) {
		t.Run("route/"+system, func(t *testing.T) {
			log.Reset()
			matrix, e := AdmissionMatrix(root, map[string]string{"host": "host", "package": "routing." + system}, nix)
			if e != nil {
				t.Fatalf("%v\n%s", e, &log)
			}
			if len(matrix.Include) != 1 || matrix.Include[0].System != system {
				t.Fatal(matrix)
			}
		})
	}
}

func allBuildRunners(t *testing.T) BuildMatrix {
	t.Helper()
	matrix, err := AdmissionMatrix("", nil, func([]string, bool, []byte) ([]byte, error) {
		t.Fatal("full admission must not evaluate targets")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return matrix
}

func TestAdmissionMatrixSelectsNativeRunners(t *testing.T) {
	matrix := allBuildRunners(t)
	systems, err := matrix.Systems()
	if err != nil || !reflect.DeepEqual(systems, sortedKeys(Systems)) {
		t.Fatal(matrix, err)
	}
	source := t.TempDir()
	for system, runner := range Systems {
		for _, pkg := range []string{"", "nested.hello"} {
			t.Run(system+"/"+pkg, func(t *testing.T) {
				selection := map[string]string{"host": "host"}
				attribute := "nixosConfigurations.host.config.system.build.toplevel"
				if pkg != "" {
					selection["package"] = pkg
					attribute = "nixosConfigurations.host.pkgs." + pkg
				}
				matrix, err := AdmissionMatrix(source, selection, func(args []string, capture bool, data []byte) ([]byte, error) {
					if !capture || len(data) != 0 || args[0] != "eval" || !strings.Contains(strings.Join(args, " "), "#"+attribute) {
						t.Fatal(args, capture, string(data))
					}
					return json.Marshal(system)
				})
				if err != nil || !reflect.DeepEqual(matrix.Include, []BuildRunner{{System: system, Runner: runner}}) {
					t.Fatal(matrix, err)
				}
			})
		}
	}
}

func TestAdmissionRejectsInvalidSelectionsAndEvaluation(t *testing.T) {
	for _, value := range []any{nil, map[string]string{}, map[string]string{"host": "../host"}, map[string]any{"host": 1}, "host"} {
		if _, err := buildSelection(map[string]any{"selection": value}); err == nil {
			t.Fatalf("invalid selection accepted: %v", value)
		}
	}
	for _, output := range []string{`"x86_64-darwin"`, `""`, `null`, `{}`, `invalid`} {
		matrix, err := AdmissionMatrix(t.TempDir(), map[string]string{"host": "host"}, func([]string, bool, []byte) ([]byte, error) {
			return []byte(output), nil
		})
		if err == nil || len(matrix.Include) != 0 {
			t.Fatal(output, matrix, err)
		}
	}
	failure := errors.New("evaluation failed")
	matrix, err := AdmissionMatrix(t.TempDir(), map[string]string{"host": "host"}, func([]string, bool, []byte) ([]byte, error) {
		return nil, failure
	})
	if !errors.Is(err, failure) || len(matrix.Include) != 0 {
		t.Fatal(matrix, err)
	}
}

func TestAdmissionMatrixRejectsMissingAndInvalidRunners(t *testing.T) {
	row := BuildRunner{System: "aarch64-linux", Runner: Systems["aarch64-linux"]}
	for _, rows := range [][]BuildRunner{
		nil,
		{row, row},
		{{System: "aarch64-linux", Runner: "macos-15"}},
		{{System: "unsupported", Runner: "self-hosted"}},
		{{}},
	} {
		if _, err := (BuildMatrix{Include: rows}).Systems(); err == nil {
			t.Fatal("invalid matrix accepted", rows)
		}
	}
}
