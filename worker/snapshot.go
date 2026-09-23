package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

const (
	CatalogTitle   = "org.opencontainers.image.title"
	CatalogLimit   = 256 * 1024 * 1024
	SnapshotFormat = "infra-ci-snapshot"
)

func DecryptBlob(storage Storage, repository string, descriptor Descriptor, identity Secret) (io.ReadCloser, error) {
	source, err := storage.Blob(repository, descriptor)
	if err != nil {
		return nil, err
	}

	stream, err := decryptedStream(source, identity)
	if err != nil {
		source.Close()
	}
	return stream, err
}

func NarinfoKey(path string) string {
	return "cache/" + strings.SplitN(filepath.Base(path), "-", 2)[0] + ".narinfo"
}

var storePathPattern = regexp.MustCompile(`^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+$`)
var recordStorePattern = regexp.MustCompile(`^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\\\n]+$`)
var recordRefPattern = regexp.MustCompile(`^[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\\\n]+$`)
var archivePattern = regexp.MustCompile(`^nar/[a-f0-9]{64}\.nar\.zst$`)

func ValidStorePath(path string) bool { return storePathPattern.MatchString(path) }

func NarinfoFields(value string) (map[string]string, error) {
	if !strings.HasPrefix(value, "StorePath: ") {
		return nil, errors.New("invalid canonical narinfo")
	}

	fields := map[string]string{}
	signed := false
	for _, line := range strings.Split(strings.TrimSuffix(value, "\n"), "\n") {
		key, text, ok := strings.Cut(line, ": ")
		_, exists := fields[key]
		if !ok || (exists && key != "Sig") {
			return nil, errors.New("invalid narinfo")
		}

		if key == "Sig" {
			signed = true
		} else {
			fields[key] = text
		}
	}

	for _, key := range []string{"StorePath", "NarHash", "NarSize", "References", "URL", "Compression"} {
		if _, ok := fields[key]; !ok {
			return nil, errors.New("incomplete narinfo")
		}
	}

	if !recordStorePattern.MatchString(fields["StorePath"]) {
		return nil, errors.New("invalid store path")
	}
	if fields["Compression"] != "zstd" || !archivePattern.MatchString(fields["URL"]) {
		return nil, errors.New("invalid archive URL")
	}

	for _, ref := range strings.Fields(fields["References"]) {
		if !recordRefPattern.MatchString(ref) {
			return nil, errors.New("invalid reference")
		}
	}

	if !signed {
		return nil, errors.New("unsigned cache record")
	}

	return fields, nil
}

type Snapshot struct {
	Storage           Storage
	Repository        string
	Files             map[string]SnapshotFile
	Narinfos          map[string]string
	Metadata          map[string]any
	Upstream          map[string][]string
	Manifest          Manifest
	Digest            string
	mu                sync.Mutex
	catalogBlobs      map[string]Descriptor
	catalogRecipients string
}

func NewSnapshot(storage Storage, repository string) *Snapshot {
	return &Snapshot{
		Storage:    storage,
		Repository: repository,
		Files:      map[string]SnapshotFile{},
		Narinfos:   map[string]string{},
		Metadata:   map[string]any{},
		Upstream:   map[string][]string{},
	}
}

// SnapshotFile identifies an independently encrypted record within an OCI blob.
type SnapshotFile struct {
	Blob   Descriptor `json:"blob"`
	Offset int64      `json:"offset"`
	Size   int64      `json:"size"`
	Digest string     `json:"digest"`
}

func wholeFile(blob Descriptor) SnapshotFile {
	return SnapshotFile{Blob: blob, Size: blob.Size, Digest: blob.Digest}
}

func (f *SnapshotFile) UnmarshalJSON(data []byte) error {
	var value struct {
		Blob   *Descriptor `json:"blob"`
		Offset *int64      `json:"offset"`
		Size   *int64      `json:"size"`
		Digest string      `json:"digest"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if value.Blob == nil || value.Offset == nil || value.Size == nil {
		return errors.New("incomplete snapshot file location")
	}
	*f = SnapshotFile{Blob: *value.Blob, Offset: *value.Offset, Size: *value.Size, Digest: value.Digest}
	return f.validate()
}

func (f SnapshotFile) validate() error {
	if !digestPattern.MatchString(f.Blob.Digest) || !digestPattern.MatchString(f.Digest) {
		return errors.New("invalid snapshot file digest")
	}
	if f.Blob.Size <= 0 || f.Blob.Size >= blobLimit || f.Size <= 0 || f.Size > f.Blob.Size || f.Offset < 0 || f.Offset > f.Blob.Size-f.Size {
		return errors.New("snapshot file range exceeds blob bounds")
	}
	if f.Size == f.Blob.Size && f.Digest != f.Blob.Digest {
		return errors.New("whole file digest differs from blob digest")
	}
	return nil
}

func LoadSnapshot(storage Storage, repository, reference string, identity Secret) (*Snapshot, error) {
	manifest, digest, err := storage.GetManifest(repository, reference)
	if err != nil {
		return nil, err
	}
	return loadSnapshot(storage, repository, manifest, digest, identity)
}

func loadSnapshot(storage Storage, repository string, manifest Manifest, digest string, identity Secret) (*Snapshot, error) {
	view, err := openCatalog(storage, repository, manifest, digest, identity)
	if err != nil {
		return nil, err
	}
	return view.loadAll(identity)
}

func (s *Snapshot) ValidateRecords() error {
	for path, refs := range s.Upstream {
		if !ValidStorePath(path) || refs == nil {
			return errors.New("invalid upstream coverage")
		}

		for _, ref := range refs {
			if !ValidStorePath(ref) {
				return errors.New("invalid upstream coverage")
			}
		}
	}

	for name, value := range s.Narinfos {
		fields, err := NarinfoFields(value)
		if err != nil {
			return err
		}

		if _, ok := s.Files["cache/"+fields["URL"]]; name != NarinfoKey(fields["StorePath"]) || !ok {
			return errors.New("narinfo references an unreachable archive")
		}
	}

	return nil
}

func (s *Snapshot) RequireClosed() error {
	if err := s.ValidateRecords(); err != nil {
		return err
	}

	paths := map[string]bool{}
	for path := range s.Upstream {
		paths[path] = true
	}

	for _, value := range s.Narinfos {
		fields, _ := NarinfoFields(value)
		paths[fields["StorePath"]] = true
	}

	for _, refs := range s.Upstream {
		for _, ref := range refs {
			if !paths[ref] {
				return errors.New("upstream coverage contains incomplete references")
			}
		}
	}

	for _, value := range s.Narinfos {
		fields, _ := NarinfoFields(value)
		for _, ref := range strings.Fields(fields["References"]) {
			if !paths["/nix/store/"+ref] {
				return errors.New("cache contains incomplete references")
			}
		}
	}

	return nil
}

func (s *Snapshot) Contains(path string) bool {
	if _, ok := s.Upstream[path]; ok {
		return true
	}

	value, ok := s.Narinfos[NarinfoKey(path)]
	return ok && strings.HasPrefix(value, "StorePath: "+path+"\n")
}

func (s *Snapshot) HasFile(name string) bool {
	_, file := s.Files[name]
	_, record := s.Narinfos[name]
	return file || record
}

func (s *Snapshot) Read(name string, identity Secret) (io.ReadCloser, error) {
	if value, ok := s.Narinfos[name]; ok {
		return io.NopCloser(strings.NewReader(value)), nil
	}

	file, ok := s.Files[name]
	if !ok {
		return nil, ErrObjectNotFound
	}

	source, err := s.Storage.BlobRange(s.Repository, file)
	if errors.Is(err, ErrObjectNotFound) {
		return nil, errors.New("snapshot file references a missing blob")
	}
	if err != nil {
		return nil, err
	}
	stream, err := decryptedStream(source, identity)
	if err != nil {
		source.Close()
	}

	return stream, err
}

func (s *Snapshot) Merge(other *Snapshot) error {
	s.reuseCatalogs(other)
	for path, refs := range other.Upstream {
		if existing, ok := s.Upstream[path]; ok && !slices.Equal(existing, refs) {
			return errors.New("conflicting upstream references")
		}

		s.Upstream[path] = slices.Clone(refs)
	}

	for name, value := range other.Narinfos {
		if existing, ok := s.Narinfos[name]; ok {
			if err := matchingNarinfos(existing, value); err != nil {
				return err
			}

		} else {
			s.Narinfos[name] = value
		}
	}

	for name, descriptor := range other.Files {
		if strings.HasPrefix(name, "cache/") {
			if _, ok := s.Files[name]; !ok || strings.HasPrefix(name, "cache/plan/") {
				s.Files[name] = descriptor
			}
		}
	}

	return nil
}

func matchingNarinfos(left, right string) error {
	if left == right {
		return nil
	}
	a, err := NarinfoFields(left)
	if err != nil {
		return err
	}
	b, err := NarinfoFields(right)
	if err != nil {
		return err
	}
	return matchingNarinfoFields(a, b)
}

func matchingNarinfoFields(left, right map[string]string) error {
	for _, key := range []string{"StorePath", "NarHash", "NarSize", "References", "URL"} {
		if left[key] != right[key] {
			return errors.New("conflicting cache record")
		}
	}
	return nil
}

func (s *Snapshot) Publish(tag string, recipients Secret) (string, error) {
	if _, err := ManifestPath(tag); err != nil {
		return "", err
	}
	if s.Metadata == nil {
		return "", errors.New("missing catalog metadata")
	}
	if err := s.ValidateRecords(); err != nil {
		return "", err
	}
	retention := snapshotRetention(s.Metadata)
	var retentionJSON []byte
	if retention.Kind != "" {
		if err := retention.validate(); err != nil {
			return "", err
		}
		retentionJSON, _ = json.Marshal(retention)
	}
	layers := map[string]Descriptor{}
	for _, file := range s.Files {
		if err := file.validate(); err != nil {
			return "", err
		}
		d := file.Blob
		if existing, ok := layers[d.Digest]; ok && (existing.Size != d.Size || existing.MediaType != d.MediaType) {
			return "", errors.New("conflicting snapshot blob descriptors")
		}
		layers[d.Digest] = d
	}

	descriptor, err := s.publishCatalog(recipients, layers)
	if err != nil {
		return "", err
	}
	descriptor.Annotations = map[string]string{CatalogTitle: "files"}
	descriptor.MediaType = catalogRootMediaType
	layers[descriptor.Digest] = descriptor

	config, err := s.Storage.UploadBlob(s.Repository, strings.NewReader("{}"), false)
	if err != nil {
		return "", err
	}

	config.MediaType = "application/octet-stream"
	descriptors := make([]Descriptor, 0, len(layers))
	for _, digest := range sortedKeys(layers) {
		descriptors = append(descriptors, layers[digest])
	}

	s.Manifest = Manifest{
		SchemaVersion: 2,
		MediaType:     manifestMediaType,
		Config:        config,
		Layers:        descriptors,
		Annotations: map[string]string{
			"org.opencontainers.image.source": "https://github.com/" + strings.TrimPrefix(s.Repository, "ghcr.io/"),
			CatalogTitle:                      "NixOS binary cache",
		},
	}
	if len(retentionJSON) != 0 {
		s.Manifest.Annotations[retentionAnnotation] = string(retentionJSON)
	}
	body, err := json.Marshal(s.Manifest)
	if err != nil {
		return "", err
	}

	if len(body) > metadataLimit {
		return "", errors.New("manifest exceeds limit")
	}

	s.Digest, err = s.Storage.PutManifest(s.Repository, tag, s.Manifest)
	return s.Digest, err
}
