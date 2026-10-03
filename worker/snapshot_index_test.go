package worker

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotIndexKeepsClosedImmutableViews(t *testing.T) {
	parent := NewSnapshot(newMemoryCache(), cacheTestRepository)
	a := cacheRecord(parent, "a")
	unrelated := cacheRecord(parent, "b")
	index, err := newSnapshotIndex(parent)
	if err != nil {
		t.Fatal(err)
	}
	before := index.snapshot
	delta := NewSnapshot(parent.Storage, parent.Repository)
	c := cacheRecord(delta, "c", filepath.Base(a))
	updated, err := index.extend(delta)
	if err != nil {
		t.Fatal(err)
	}
	if before.Contains(c) || !updated.Contains(c) {
		t.Fatal("update changed an existing view")
	}
	selected := index.selectPaths(map[string]bool{c: true, "/nix/store/00000000000000000000000000000000-missing": true})
	if !selected.Contains(a) || !selected.Contains(c) || selected.Contains(unrelated) || len(selected.Files) != 2 {
		t.Fatal("selection did not retain exactly the reference closure")
	}
	if err := selected.RequireClosed(); err != nil {
		t.Fatal(err)
	}
	upstream := NewSnapshot(parent.Storage, parent.Repository)
	upstream.Upstream[a] = []string{}
	updated, err = index.extend(upstream)
	if err != nil {
		t.Fatal(err)
	}
	selected = index.selectPaths(map[string]bool{a: true})
	if !selected.Contains(a) || len(selected.Narinfos) != 1 || len(selected.Upstream) != 1 {
		t.Fatal("upstream coverage discarded the cached archive")
	}
	broken := NewSnapshot(parent.Storage, parent.Repository)
	cacheRecord(broken, "d", strings.Repeat("0", 32)+"-missing")
	if _, err := index.extend(broken); err == nil {
		t.Fatal("accepted incomplete delta")
	}
	if index.snapshot != updated {
		t.Fatal("failed update replaced the view")
	}
	delta.Narinfos[NarinfoKey(c)] = strings.Replace(delta.Narinfos[NarinfoKey(c)], "NarSize: 3", "NarSize: 4", 1)
	if _, err := index.extend(delta); err == nil {
		t.Fatal("accepted conflicting NAR identity")
	}
	delete(delta.Narinfos, NarinfoKey(c))
	delta.Upstream[a] = []string{c}
	if _, err := index.extend(delta); err == nil {
		t.Fatal("accepted conflicting upstream closure")
	}
}

func TestSnapshotIndexValidatesNewRecords(t *testing.T) {
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.Narinfos["invalid"] = "" },
		func(s *Snapshot) {
			for n := range s.Files {
				delete(s.Files, n)
			}
		},
		func(s *Snapshot) {
			for n, v := range s.Files {
				v.Size = -1
				s.Files[n] = v
			}
		},
		func(s *Snapshot) { s.Upstream["invalid"] = []string{} },
		func(s *Snapshot) { s.Upstream["/nix/store/00000000000000000000000000000000-empty"] = nil },
	} {
		snapshot := NewSnapshot(newMemoryCache(), cacheTestRepository)
		cacheRecord(snapshot, "a")
		mutate(snapshot)
		if _, err := newSnapshotIndex(snapshot); err == nil {
			t.Fatal("invalid snapshot indexed")
		}
	}
}
