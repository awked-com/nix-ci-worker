package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const evaluationPlanLimit = 64 * 1024 * 1024

type cachedEvaluation struct {
	Key  string `json:"key"`
	Plan *Plan  `json:"plan"`
}

func evaluationFile(system string) string { return "cache/plan/" + system + ".json.zst" }

func evaluationKey(revision, version, system string, selection map[string]string) string {
	raw, _ := json.Marshal([]any{"evaluation-1", Policy, revision, version, system, selection})
	return contentDigest(raw)
}

func sourceEvaluationKey(source, system string, selection map[string]string, nix NixFunc) (string, error) {
	// A commit identifies the input only in a clean checkout. Local fixture and
	// uncommitted builds still evaluate normally and never replace a saved plan.
	revision, err := runCommand(source, io.Discard, "git", "rev-parse", "HEAD")
	if err != nil {
		return "", nil
	}
	status, err := runCommand(source, io.Discard, "git", "status", "--porcelain", "--ignored", "--untracked-files=all")
	if err != nil || len(status) != 0 {
		return "", nil
	}
	version, err := nix([]string{"--version"}, true, nil)
	if err != nil {
		return "", err
	}
	return evaluationKey(strings.TrimSpace(string(revision)), strings.TrimSpace(string(version)), system, selection), nil
}

func loadEvaluation(source, system, key string, parent *Snapshot, identity, signingKey Secret, log io.Writer) (*Plan, error) {
	if key == "" || !parent.HasFile(evaluationFile(system)) {
		return nil, nil
	}
	stream, err := parent.Read(evaluationFile(system), identity)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	decoder, err := zstd.NewReader(stream, zstd.WithDecoderMaxMemory(evaluationPlanLimit), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	raw, err := readLimited(decoder, evaluationPlanLimit)
	decoder.Close()
	if err == nil {
		_, err = io.Copy(io.Discard, stream)
	}
	if err != nil {
		return nil, err
	}
	var saved cachedEvaluation
	if err = json.Unmarshal(raw, &saved); err != nil {
		return nil, errors.New("invalid cached evaluation")
	}
	if saved.Key != key {
		return nil, nil
	}
	if saved.Plan == nil {
		return nil, errors.New("missing cached evaluation plan")
	}
	plan, err := NewPlan(saved.Plan.Targets, saved.Plan.Derivations, sortedKeys(saved.Plan.Required))
	if err != nil || !equivalent(plan, saved.Plan) {
		return nil, errors.New("invalid cached evaluation plan")
	}
	if _, err := plan.Batches(nil, 1); err != nil {
		return nil, err
	}
	for drv, value := range plan.Derivations {
		if value.Dynamic || !parent.Contains(drv) {
			return nil, nil
		}
		for _, src := range value.InputSrcs {
			if !parent.Contains(src) {
				return nil, nil
			}
		}
	}
	public, err := signingPublicKey(signingKey.Data)
	if err != nil {
		return nil, err
	}
	roots := map[string]bool{}
	for _, drv := range plan.Targets {
		roots[drv] = true
	}
	if err = poolCopy(context.Background(), source, parent, identity, public, sortedKeys(roots), log); err != nil {
		return nil, err
	}
	fmt.Fprintln(log, "Evaluation cache: restored plan and derivations")
	return plan, nil
}

func saveEvaluation(system, key string, plan *Plan, snapshot *Snapshot, recipients Secret) error {
	if key == "" {
		return nil
	}
	if !plan.Static() {
		return nil
	}
	raw, err := json.Marshal(cachedEvaluation{Key: key, Plan: plan})
	if err != nil {
		return err
	}
	if len(raw) > evaluationPlanLimit {
		// Oversized plans still build normally; they only forgo reuse.
		return nil
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return err
	}
	compressed := encoder.EncodeAll(raw, nil)
	encoder.Close()
	stream, err := EncryptedStream(bytes.NewReader(compressed), recipients)
	if err != nil {
		return err
	}
	descriptor, err := snapshot.Storage.UploadBlob(snapshot.Repository, stream, true)
	stream.Close()
	if err != nil {
		return err
	}
	snapshot.Files[evaluationFile(system)] = wholeFile(descriptor)
	return nil
}
