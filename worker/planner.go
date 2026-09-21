package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const Policy = "native-upstream-2"

var Systems = map[string]string{
	"x86_64-linux":   "ubuntu-24.04",
	"aarch64-linux":  "ubuntu-24.04-arm",
	"aarch64-darwin": "macos-15",
}
var nativeName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var attributeName = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$`)

type Derivation struct {
	System    string                      `json:"system"`
	Env       map[string]string           `json:"env"`
	InputDrvs map[string]derivationInput  `json:"inputDrvs"`
	InputSrcs []string                    `json:"inputSrcs"`
	Dynamic   bool                        `json:"dynamic"`
	Outputs   map[string]derivationOutput `json:"outputs"`
}

type derivationInput struct {
	Outputs        []string                   `json:"outputs"`
	DynamicOutputs map[string]json.RawMessage `json:"dynamicOutputs,omitempty"`
}

type derivationOutput struct {
	Path string `json:"path"`
}

type Plan struct {
	Targets     map[string]string
	Derivations map[string]Derivation
	Required    map[string]bool
	Outputs     map[string]map[string]string
}

type NixFunc func(arguments []string, capture bool, data []byte) ([]byte, error)

type Coverage interface{ Contains(string) bool }

// Import direct dependency outputs and let substitution fetch their runtime
// references. Importing their entire build graphs would also fetch compilers
// and intermediate outputs that this derivation does not use.
func (p *Plan) BuildInputs(drv string) ([]string, error) {
	d, exists := p.Derivations[drv]
	if !exists || !ValidStorePath(drv) || d.Dynamic {
		return nil, errors.New("invalid static build derivation")
	}
	paths := map[string]bool{drv: true}
	for _, path := range d.InputSrcs {
		paths[path] = true
	}
	for dependency, input := range d.InputDrvs {
		if input.Outputs == nil || len(input.DynamicOutputs) != 0 {
			return nil, errors.New("invalid static build dependency")
		}
		outputs, exists := p.Outputs[dependency]
		if !exists {
			return nil, errors.New("missing build dependency")
		}
		for _, name := range input.Outputs {
			paths[outputs[name]] = true
		}
	}
	for path := range paths {
		if !ValidStorePath(path) {
			return nil, errors.New("invalid or unresolved build input")
		}
	}
	return sortedKeys(paths), nil
}

func (p *Plan) Static() bool {
	for _, drv := range p.Derivations {
		if drv.Dynamic {
			return false
		}
		for _, output := range drv.Outputs {
			if output.Path == "" {
				return false
			}
		}
	}
	return true
}

func NewPlan(targets map[string]string, derivations map[string]Derivation, requisites []string) (*Plan, error) {
	if len(targets) == 0 {
		return nil, errors.New("invalid native targets")
	}

	p := &Plan{targets, derivations, map[string]bool{}, map[string]map[string]string{}}
	for name, drv := range targets {
		if !nativeName.MatchString(name) {
			return nil, errors.New("invalid native targets")
		}

		if _, ok := derivations[drv]; !ok {
			return nil, errors.New("missing target derivation")
		}
	}

	for _, v := range requisites {
		p.Required[v] = true
	}

	for drv, value := range derivations {
		if !strings.HasPrefix(drv, "/nix/store/") || !strings.HasSuffix(drv, ".drv") {
			return nil, errors.New("invalid derivation")
		}

		p.Required[drv] = true
		for _, v := range value.InputSrcs {
			p.Required[v] = true
		}

		p.Outputs[drv] = map[string]string{}
		for name, out := range value.Outputs {
			p.Outputs[drv][name] = out.Path
			if out.Path != "" {
				p.Required[out.Path] = true
			}
		}
	}

	return p, nil
}

func sortedKeys[V any](m map[string]V) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}

	sort.Strings(r)
	return r
}

func (p *Plan) Hash() string {
	b, _ := json.Marshal(map[string]any{
		"targets":  p.Targets,
		"outputs":  p.Outputs,
		"required": sortedKeys(p.Required),
		"policy":   Policy,
	})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (p *Plan) Complete(s Coverage) bool {
	for _, d := range p.Derivations {
		if d.Dynamic {
			return false
		}
	}

	for _, os := range p.Outputs {
		for _, path := range os {
			if path == "" {
				return false
			}
		}
	}

	for path := range p.Required {
		if !s.Contains(path) {
			return false
		}
	}

	return true
}

func (p *Plan) Missing(s Coverage, local map[string]bool) []string {
	r := []string{}
	for _, drv := range sortedKeys(p.Outputs) {
		names := []string{}
		for _, n := range sortedKeys(p.Outputs[drv]) {
			path := p.Outputs[drv][n]
			if path == "" || (!s.Contains(path) && !local[path]) {
				names = append(names, n)
			}
		}

		if len(names) > 0 {
			r = append(r, drv+"^"+strings.Join(names, ","))
		}
	}

	return r
}

func (p *Plan) Batches(missing []string, limit int) ([][]string, error) {
	if limit < 1 {
		return nil, errors.New("invalid batch size")
	}

	selected := map[string]string{}
	for _, s := range missing {
		selected[strings.SplitN(s, "^", 2)[0]] = s
	}

	counts := map[string]int{}
	consumers := map[string][]string{}
	ready := []string{}
	for drv, d := range p.Derivations {
		counts[drv] = len(d.InputDrvs)
		if len(d.InputDrvs) == 0 {
			ready = append(ready, drv)
		}

		for dep := range d.InputDrvs {
			if _, ok := p.Derivations[dep]; !ok {
				return nil, errors.New("missing dependency derivation")
			}

			consumers[dep] = append(consumers[dep], drv)
		}
	}

	ordered := []string{}
	visited := 0
	for len(ready) > 0 {
		sort.Strings(ready)
		drv := ready[0]
		ready = ready[1:]
		visited++
		if v, ok := selected[drv]; ok {
			ordered = append(ordered, v)
		}

		for _, c := range consumers[drv] {
			counts[c]--
			if counts[c] == 0 {
				ready = append(ready, c)
			}
		}
	}

	if visited != len(p.Derivations) {
		return nil, errors.New("cyclic derivation graph")
	}

	batches := [][]string{}
	for len(ordered) > 0 {
		n := min(limit, len(ordered))
		batches = append(batches, ordered[:n])
		ordered = ordered[n:]
	}

	return batches, nil
}

func (p *Plan) TargetPaths(root string) (map[string]bool, bool) {
	pending := []string{root}
	seen := map[string]bool{}
	paths := map[string]bool{}
	unresolved := false
	for len(pending) > 0 {
		drv := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[drv] {
			continue
		}

		seen[drv] = true
		d, ok := p.Derivations[drv]
		if !ok {
			return paths, true
		}

		paths[drv] = true
		unresolved = unresolved || d.Dynamic
		for _, v := range d.InputSrcs {
			paths[v] = true
		}

		for _, v := range p.Outputs[drv] {
			if v == "" {
				unresolved = true
			} else {
				paths[v] = true
			}
		}

		for dep := range d.InputDrvs {
			pending = append(pending, dep)
		}
	}

	return paths, unresolved
}

func (p *Plan) Resolve(nix NixFunc) error {
	for drv, outputs := range p.Outputs {
		unresolved := false
		for _, v := range outputs {
			unresolved = unresolved || v == ""
		}

		if !unresolved {
			continue
		}

		b, e := nix([]string{"build", "--no-link", "--json", "--offline", "--max-jobs", "0", drv + "^*"}, true, nil)
		if e != nil {
			continue
		}

		var rows []struct {
			Outputs map[string]string `json:"outputs"`
		}
		if e = json.Unmarshal(b, &rows); e != nil {
			return e
		}

		if len(rows) == 0 {
			return errors.New("missing resolved outputs")
		}

		resolved := rows[0].Outputs
		if !slices.Equal(sortedKeys(resolved), sortedKeys(outputs)) {
			return errors.New("resolved output set differs from derivation")
		}

		p.Outputs[drv] = resolved
		for _, v := range resolved {
			p.Required[v] = true
		}
	}

	return nil
}

func (p *Plan) Results(s Coverage, system string) []map[string]any {
	result := []map[string]any{}
	for _, name := range sortedKeys(p.Targets) {
		drv := p.Targets[name]
		paths, unresolved := p.TargetPaths(drv)
		missing := []string{}
		for _, path := range sortedKeys(paths) {
			if !s.Contains(path) {
				missing = append(missing, path)
			}
		}

		status := "success"
		if unresolved || len(missing) > 0 {
			status = "failure"
		}

		result = append(result, map[string]any{
			"kind":   "target",
			"target": name,
			"system": system,
			"status": status,
			"results": []map[string]any{
				{
					"drvPath": drv,
					"outputs": p.Outputs[drv],
				},
			},
			"missing": missing,
		})
	}

	return result
}

func ValidateSelection(s map[string]string) error {
	if len(s) == 0 || !nativeName.MatchString(s["host"]) {
		return errors.New("build selection needs a valid host name")
	}

	for k := range s {
		if k != "host" && k != "package" {
			return errors.New("build selection needs a valid host name")
		}
	}

	if v, ok := s["package"]; ok && !attributeName.MatchString(v) {
		return errors.New("package must be a dotted attribute path")
	}

	return nil
}

func buildSelection(metadata map[string]any) (map[string]string, error) {
	v, ok := metadata["selection"]
	if !ok {
		return nil, nil
	}
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var selection map[string]string
	if e = json.Unmarshal(b, &selection); e != nil {
		return nil, e
	}
	return selection, ValidateSelection(selection)
}

func selectedAttribute(s map[string]string) (string, string, error) {
	if e := ValidateSelection(s); e != nil {
		return "", "", e
	}

	host := s["host"]
	attribute := "nixosConfigurations." + host + "."
	name := "host-" + host
	if pkg, ok := s["package"]; ok {
		attribute += "pkgs." + pkg
		name = "package-" + host + "-" + strings.ReplaceAll(pkg, ".", "-")
	} else {
		attribute += "config.system.build.toplevel"
	}
	return attribute, name, nil
}

func SelectedTargets(source string, s map[string]string, nix NixFunc) (string, map[string]string, error) {
	attribute, name, e := selectedAttribute(s)
	if e != nil {
		return "", nil, e
	}

	b, e := nix([]string{
		"eval",
		"--json",
		"--no-write-lock-file",
		"path:" + source + "#" + attribute,
		"--apply",
		"value: { inherit (value) system drvPath; }",
	}, true, nil)
	if e != nil {
		return "", nil, e
	}

	var target struct {
		System  string `json:"system"`
		DrvPath string `json:"drvPath"`
	}
	if e = json.Unmarshal(b, &target); e != nil {
		return "", nil, e
	}

	if _, ok := Systems[target.System]; !ok {
		return "", nil, errors.New("selected target has no native CI runner")
	}

	return target.System, map[string]string{name: target.DrvPath}, nil
}

func flakeSourcePath(source string) (string, error) {
	source, e := filepath.Abs(source)
	if e != nil {
		return "", e
	}

	// Nix path inputs reject symlink ancestors, including macOS /tmp.
	return filepath.EvalSymlinks(source)
}

func Evaluate(source, system string, nix NixFunc, selection map[string]string, log io.Writer) (*Plan, error) {
	started := time.Now()
	source, e := flakeSourcePath(source)
	if e != nil {
		return nil, e
	}

	var targets map[string]string
	if selection != nil {
		native, t, e := SelectedTargets(source, selection, nix)
		if e != nil {
			return nil, e
		}
		if native != system {
			return nil, errors.New("selected target does not match the admitted runner")
		}

		targets = t
	} else {
		b, e := nix([]string{
			"eval",
			"--json",
			"--no-write-lock-file",
			"path:" + source + "#hydraJobs." + system,
			"--apply",
			"builtins.mapAttrs (_: value: value.drvPath)",
		}, true, nil)
		if e != nil {
			return nil, e
		}

		if e = json.Unmarshal(b, &targets); e != nil {
			return nil, e
		}
	}
	fmt.Fprintf(log, "Target evaluation finished (%.1fs)\n", time.Since(started).Seconds())

	started = time.Now()
	roots := map[string]bool{}
	for _, drv := range targets {
		roots[drv] = true
	}

	data := []byte(strings.Join(sortedKeys(roots), "\n") + "\n")
	b, e := nix([]string{"derivation", "show", "--recursive", "--stdin"}, true, data)
	if e != nil {
		return nil, e
	}
	fmt.Fprintf(log, "Derivation export finished (%.1fs)\n", time.Since(started).Seconds())

	started = time.Now()
	var raw struct {
		Version     int `json:"version"`
		Derivations map[string]struct {
			System string `json:"system"`
			Inputs struct {
				Drvs map[string]derivationInput `json:"drvs"`
				Srcs []string                   `json:"srcs"`
			} `json:"inputs"`
			Outputs map[string]struct {
				Path string `json:"path"`
				Hash string `json:"hash"`
			} `json:"outputs"`
			Env map[string]string `json:"env"`
		} `json:"derivations"`
	}
	if e = json.Unmarshal(b, &raw); e != nil {
		return nil, e
	}

	if raw.Version != 4 {
		return nil, errors.New("unexpected pinned Nix derivation schema")
	}

	ds := map[string]Derivation{}
	for name, v := range raw.Derivations {
		d := Derivation{
			System:    v.System,
			Env:       v.Env,
			InputDrvs: map[string]derivationInput{},
			Outputs:   map[string]derivationOutput{},
		}
		for dep, value := range v.Inputs.Drvs {
			d.InputDrvs["/nix/store/"+dep] = value
			d.Dynamic = d.Dynamic || len(value.DynamicOutputs) > 0
		}

		for _, s := range v.Inputs.Srcs {
			d.InputSrcs = append(d.InputSrcs, "/nix/store/"+s)
		}

		for key, out := range v.Outputs {
			path := ""
			if out.Path != "" {
				path = "/nix/store/" + out.Path
			} else if out.Hash != "" && storePathRE.MatchString(v.Env[key]) {
				path = v.Env[key]
			}

			d.Outputs[key] = derivationOutput{Path: path}
		}

		ds["/nix/store/"+name] = d
	}
	fmt.Fprintf(log, "Derivation decoding finished (%.1fs)\n", time.Since(started).Seconds())

	started = time.Now()
	b, e = nix([]string{"path-info", "--recursive", "--stdin"}, true, data)
	if e != nil {
		return nil, e
	}
	fmt.Fprintf(log, "Derivation closure lookup finished (%.1fs)\n", time.Since(started).Seconds())

	return NewPlan(targets, ds, strings.Fields(string(b)))
}
