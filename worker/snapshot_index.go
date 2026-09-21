package worker

import (
	"errors"
	"maps"
	"slices"
	"strings"
)

type indexedPath struct {
	text   string
	fields map[string]string
	refs   []string
}

// An index owns an immutable view. Updates validate changed records and their
// references before replacing it; readers can continue using the previous view.
type snapshotIndex struct {
	snapshot *Snapshot
	paths    map[string]indexedPath
}

func newSnapshotIndex(snapshot *Snapshot) (*snapshotIndex, error) {
	index := &snapshotIndex{snapshot: NewSnapshot(snapshot.Storage, snapshot.Repository), paths: map[string]indexedPath{}}
	index.snapshot.Digest = snapshot.Digest
	if _, err := index.extend(snapshot); err != nil {
		return nil, err
	}
	return index, nil
}

func (i *snapshotIndex) extend(delta *Snapshot) (*Snapshot, error) {
	view := NewSnapshot(i.snapshot.Storage, i.snapshot.Repository)
	view.Digest = i.snapshot.Digest
	view.Files = maps.Clone(i.snapshot.Files)
	view.Narinfos = maps.Clone(i.snapshot.Narinfos)
	view.Upstream = maps.Clone(i.snapshot.Upstream)
	paths := maps.Clone(i.paths)
	changed := []string{}
	for name, file := range delta.Files {
		if _, exists := view.Files[name]; !exists {
			if err := file.validate(); err != nil {
				return nil, err
			}
			view.Files[name] = file
		}
	}
	for path, refs := range delta.Upstream {
		if !ValidStorePath(path) || refs == nil {
			return nil, errors.New("invalid upstream coverage")
		}
		if previous, exists := paths[path]; exists && !slices.Equal(previous.refs, refs) {
			return nil, errors.New("conflicting cached and upstream references")
		}
		if _, exists := view.Upstream[path]; exists {
			continue
		}
		for _, ref := range refs {
			if !ValidStorePath(ref) {
				return nil, errors.New("invalid upstream coverage")
			}
		}
		view.Upstream[path] = slices.Clone(refs)
		if _, exists := paths[path]; !exists {
			paths[path] = indexedPath{refs: view.Upstream[path]}
		}
		changed = append(changed, path)
	}
	for name, text := range delta.Narinfos {
		if existing, exists := view.Narinfos[name]; exists && existing == text {
			continue
		}
		fields, err := NarinfoFields(text)
		if err != nil {
			return nil, err
		}
		path := fields["StorePath"]
		if _, exists := view.Files["cache/"+fields["URL"]]; !exists || name != NarinfoKey(path) {
			return nil, errors.New("narinfo references an unreachable archive")
		}
		if old := view.Narinfos[name]; old != "" {
			previous, err := NarinfoFields(old)
			if err != nil {
				return nil, err
			}
			for _, key := range []string{"StorePath", "NarHash", "NarSize", "References", "URL"} {
				if previous[key] != fields[key] {
					return nil, errors.New("conflicting cache record")
				}
			}
			continue
		}
		refs := []string{}
		for _, ref := range strings.Fields(fields["References"]) {
			refs = append(refs, "/nix/store/"+ref)
		}
		if upstream, exists := view.Upstream[path]; exists && !slices.Equal(upstream, refs) {
			return nil, errors.New("conflicting cached and upstream references")
		}
		view.Narinfos[name] = text
		paths[path] = indexedPath{text: text, fields: fields, refs: refs}
		changed = append(changed, path)
	}
	for _, path := range changed {
		for _, ref := range paths[path].refs {
			if _, exists := paths[ref]; !exists {
				return nil, errors.New("cache contains incomplete references")
			}
		}
	}
	i.snapshot, i.paths = view, paths
	return view, nil
}

// Missing roots are unbuilt outputs. References of available roots must always
// be present; retaining their full closure keeps a selected catalog standalone.
func (i *snapshotIndex) selectPaths(roots map[string]bool) *Snapshot {
	selected := NewSnapshot(i.snapshot.Storage, i.snapshot.Repository)
	selected.Digest = i.snapshot.Digest
	seen := map[string]bool{}
	pending := sortedKeys(roots)
	for len(pending) > 0 {
		path := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[path] {
			continue
		}
		seen[path] = true
		record, exists := i.paths[path]
		if !exists {
			continue
		}
		pending = append(pending, record.refs...)
		if refs, upstream := i.snapshot.Upstream[path]; upstream {
			selected.Upstream[path] = refs
		}
		if record.text != "" {
			selected.Narinfos[NarinfoKey(path)] = record.text
			archive := "cache/" + record.fields["URL"]
			selected.Files[archive] = i.snapshot.Files[archive]
		}
	}
	return selected
}
