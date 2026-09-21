package worker

import (
	"encoding/json"
	"errors"
	"fmt"
)

type BuildRunner struct {
	System string `json:"system"`
	Runner string `json:"runner"`
}

type BuildMatrix struct {
	Include []BuildRunner `json:"include"`
}

type HelperRunner struct {
	System  string `json:"system"`
	Runner  string `json:"runner"`
	Builder int    `json:"builder"`
}

func (m BuildMatrix) Helpers() (map[string][]HelperRunner, error) {
	systems, err := m.Systems()
	if err != nil {
		return nil, err
	}
	rows := []HelperRunner{}
	for _, system := range systems {
		for builder := 1; builder < RunnersPerSystem; builder++ {
			rows = append(rows, HelperRunner{system, Systems[system], builder})
		}
	}
	return map[string][]HelperRunner{"include": rows}, nil
}

func (m BuildMatrix) Systems() ([]string, error) {
	if len(m.Include) == 0 {
		return nil, errors.New("missing admission matrix")
	}
	systems := []string{}
	seen := map[string]bool{}
	for _, row := range m.Include {
		runner, ok := Systems[row.System]
		if !ok || runner != row.Runner || seen[row.System] {
			return nil, errors.New("invalid admission matrix")
		}
		seen[row.System] = true
		systems = append(systems, row.System)
	}
	return systems, nil
}

func AdmissionMatrix(source string, selection map[string]string, nix NixFunc) (BuildMatrix, error) {
	matrix := BuildMatrix{}
	systems := sortedKeys(Systems)
	if selection != nil {
		attribute, _, e := selectedAttribute(selection)
		if e != nil {
			return matrix, e
		}
		source, e = flakeSourcePath(source)
		if e != nil {
			return matrix, e
		}
		// Routing needs only the derivation's platform, not its build graph.
		b, e := nix([]string{"eval", "--json", "--no-write-lock-file", "path:" + source + "#" + attribute, "--apply", "value: value.system"}, true, nil)
		if e != nil {
			return matrix, e
		}
		var system string
		if e = json.Unmarshal(b, &system); e != nil {
			return matrix, e
		}
		if _, ok := Systems[system]; !ok {
			return matrix, errors.New("selected target has no native CI runner")
		}
		systems = []string{system}
	}
	for _, system := range systems {
		matrix.Include = append(matrix.Include, BuildRunner{System: system, Runner: Systems[system]})
	}
	return matrix, nil
}

func String(v any) string {
	if v == nil {
		return ""
	}

	return fmt.Sprint(v)
}

func Int(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}

	return 0
}

func JobLogicalName(name string) string {
	for system := range Systems {
		if name == "Build "+system {
			return system
		}
	}
	if name == "admit" || name == "finalize" {
		return name
	}
	return ""
}

type ActionJob struct {
	ID         uint64 `json:"id"`
	Name       string `json:"name"`
	RunAttempt int    `json:"run_attempt"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

func ActionJobs(api GitHubAPI, repository, run string, attempt int) (map[string]ActionJob, error) {
	if attempt < 1 || !regexpRun.MatchString(run) || run[0] == '0' {
		return nil, errors.New("invalid workflow attempt")
	}
	selected := map[string]ActionJob{}
	for previous := attempt; previous > 0; previous-- {
		response, err := api(fmt.Sprintf("repos/%s/actions/runs/%s/attempts/%d/jobs?per_page=100", repository, run, previous), "GET")
		if err != nil {
			return nil, err
		}
		var inventory struct {
			TotalCount *int        `json:"total_count"`
			Jobs       []ActionJob `json:"jobs"`
		}
		raw, err := json.Marshal(response)
		if err != nil || json.Unmarshal(raw, &inventory) != nil {
			return nil, errors.New("invalid GitHub job inventory")
		}
		if inventory.TotalCount == nil || inventory.Jobs == nil || *inventory.TotalCount > 100 || *inventory.TotalCount != len(inventory.Jobs) {
			return nil, errors.New("unexpected job inventory")
		}
		for _, job := range inventory.Jobs {
			if job.ID == 0 || job.Name == "" || job.Status == "" || job.RunAttempt != previous {
				return nil, errors.New("invalid GitHub job inventory")
			}
			logical := JobLogicalName(job.Name)
			_, exists := selected[logical]
			if logical != "" && !exists && job.Conclusion != "skipped" {
				selected[logical] = job
			}
		}
	}
	return selected, nil
}
