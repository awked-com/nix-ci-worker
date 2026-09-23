package worker

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Nodes are split by the SHA-256 of the cache key. The tree keeps both the
// discovery root and individual lookups bounded as the cumulative cache grows.
const catalogNodeLimit = 128 * 1024
const catalogRootLimit = 16 * 1024
const catalogRootMediaType = "application/vnd.awked.nix-ci.catalog.v3+age"

type catalogRoot struct {
	Format     string     `json:"format"`
	Version    int        `json:"version"`
	Index      Descriptor `json:"index"`
	Writer     Descriptor `json:"writer"`
	Metadata   Descriptor `json:"metadata"`
	Recipients string     `json:"recipients"`
}

type catalogRecord struct {
	File       *SnapshotFile `json:"file,omitempty"`
	Narinfo    string        `json:"narinfo,omitempty"`
	Archive    *SnapshotFile `json:"archive,omitempty"`
	References *[]string     `json:"references,omitempty"`
}

type catalogNode struct {
	Records  map[string]catalogRecord `json:"records"`
	Children map[string]Descriptor    `json:"children,omitempty"`
}

type catalogView struct {
	storage    Storage
	repository string
	manifest   Manifest
	digest     string
	root       catalogRoot
	reachable  map[string]Descriptor
	legacy     *Snapshot
	nodes      map[string]catalogNode
	prefixes   map[string]string
	blobs      map[string]Descriptor
}

// Reusing encrypted blobs is safe only while the recipient set is unchanged.
func (s *Snapshot) reuseCatalogs(previous *Snapshot) {
	if previous == nil || previous.catalogRecipients == "" {
		return
	}
	if s.catalogRecipients != "" && s.catalogRecipients != previous.catalogRecipients {
		return
	}
	s.catalogRecipients = previous.catalogRecipients
	if s.catalogBlobs == nil {
		s.catalogBlobs = map[string]Descriptor{}
	}
	for hash, descriptor := range previous.catalogBlobs {
		s.catalogBlobs[hash] = descriptor
	}
}

func consumerFile(name string) bool {
	return strings.HasPrefix(name, "cache/") && ValidCachePath(strings.TrimPrefix(name, "cache/"))
}

func (s *Snapshot) publishCatalog(recipients Secret, layers map[string]Descriptor) (Descriptor, error) {
	recipientHash := contentDigest(recipients.Data)
	if s.catalogRecipients != recipientHash {
		s.catalogBlobs = nil
	}
	if s.catalogBlobs == nil {
		s.catalogBlobs = map[string]Descriptor{}
	}
	s.catalogRecipients = recipientHash
	reused := map[string]Descriptor{}
	upload := func(data any, limit int) (Descriptor, error) {
		raw, err := json.Marshal(data)
		if err != nil {
			return Descriptor{}, err
		}
		if len(raw) > limit {
			return Descriptor{}, errors.New("catalog exceeds limit")
		}
		hash := contentDigest(raw)
		descriptor, ok := reused[hash]
		if !ok {
			descriptor, ok = s.catalogBlobs[hash]
		}
		if !ok {
			var compressed bytes.Buffer
			writer, _ := gzip.NewWriterLevel(&compressed, 3)
			if _, err = writer.Write(raw); err != nil {
				return Descriptor{}, err
			}
			if err = writer.Close(); err != nil {
				return Descriptor{}, err
			}
			stream, err := EncryptedStream(&compressed, recipients)
			if err != nil {
				return Descriptor{}, err
			}
			descriptor, err = s.Storage.UploadBlob(s.Repository, stream, true)
			stream.Close()
			if err != nil {
				return Descriptor{}, err
			}
		}
		reused[hash], layers[descriptor.Digest] = descriptor, descriptor
		return descriptor, nil
	}
	records := map[string]catalogRecord{}
	writer := map[string]catalogRecord{}
	for name, file := range s.Files {
		if consumerFile(name) {
			records[name] = catalogRecord{File: &file}
		} else {
			writer[name] = catalogRecord{File: &file}
		}
	}
	for name, text := range s.Narinfos {
		fields, err := NarinfoFields(text)
		if err != nil {
			return Descriptor{}, err
		}
		record := records[name]
		archive := s.Files["cache/"+fields["URL"]]
		record.Narinfo, record.Archive = text, &archive
		records[name] = record
	}
	for path, refs := range s.Upstream {
		record := writer[path]
		record.References = &refs
		writer[path] = record
	}
	// Validate and partition both trees before uploading any new catalog blobs.
	consumerPlan, err := partitionCatalog(records, 0)
	if err != nil {
		return Descriptor{}, err
	}
	writerPlan, err := partitionCatalog(writer, 0)
	if err != nil {
		return Descriptor{}, err
	}
	metadata, err := json.Marshal(s.Metadata)
	if err != nil {
		return Descriptor{}, err
	}
	if len(metadata) > CatalogLimit {
		return Descriptor{}, errors.New("catalog exceeds limit")
	}
	var publishTree func(*catalogPartition) (Descriptor, error)
	publishTree = func(plan *catalogPartition) (Descriptor, error) {
		node := catalogNode{Records: plan.records}
		if plan.children != nil {
			node.Children = map[string]Descriptor{}
			for _, nibble := range sortedKeys(plan.children) {
				descriptor, err := publishTree(plan.children[nibble])
				if err != nil {
					return Descriptor{}, err
				}
				node.Children[nibble] = descriptor
			}
		}
		return upload(node, catalogNodeLimit)
	}
	index, err := publishTree(consumerPlan)
	if err != nil {
		return Descriptor{}, err
	}
	state, err := publishTree(writerPlan)
	if err != nil {
		return Descriptor{}, err
	}
	meta, err := upload(json.RawMessage(metadata), CatalogLimit)
	if err != nil {
		return Descriptor{}, err
	}
	root, err := upload(catalogRoot{Format: SnapshotFormat, Version: 3, Index: index, Writer: state, Metadata: meta, Recipients: recipientHash}, catalogRootLimit)
	if err == nil {
		s.catalogBlobs = reused
	}

	return root, err
}

type catalogPartition struct {
	records  map[string]catalogRecord
	children map[string]*catalogPartition
}

func partitionCatalog(records map[string]catalogRecord, depth int) (*catalogPartition, error) {
	raw, err := json.Marshal(catalogNode{Records: records})
	if err != nil {
		return nil, err
	}
	if len(raw) <= catalogNodeLimit {
		return &catalogPartition{records: records}, nil
	}
	if len(records) == 1 || depth == 64 {
		return nil, errors.New("cache record exceeds catalog node limit")
	}
	groups := map[string]map[string]catalogRecord{}
	for name, record := range records {
		nibble := contentDigest([]byte(name))[7+depth : 8+depth]
		if groups[nibble] == nil {
			groups[nibble] = map[string]catalogRecord{}
		}
		groups[nibble][name] = record
	}
	plan := &catalogPartition{children: map[string]*catalogPartition{}}
	for _, nibble := range sortedKeys(groups) {
		child, err := partitionCatalog(groups[nibble], depth+1)
		if err != nil {
			return nil, err
		}
		plan.children[nibble] = child
	}
	return plan, nil
}

func readCatalogBlob(storage Storage, repository string, descriptor Descriptor, identity Secret, limit int) ([]byte, error) {
	// Also bound ciphertext size before any decompression or allocation.
	if descriptor.Size <= 0 || descriptor.Size > int64(limit)+1024*1024 {
		return nil, errors.New("catalog ciphertext exceeds limit")
	}
	stream, err := DecryptBlob(storage, repository, descriptor, identity)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	compressed, err := gzip.NewReader(stream)
	if err != nil {
		return nil, err
	}
	raw, err := readLimited(compressed, limit)
	compressed.Close()
	if err == nil {
		_, err = io.Copy(io.Discard, stream)
	}
	return raw, err
}

func openCatalog(storage Storage, repository string, manifest Manifest, digest string, identity Secret) (*catalogView, error) {
	view := &catalogView{storage: storage, repository: repository, manifest: manifest, digest: digest, reachable: map[string]Descriptor{}, nodes: map[string]catalogNode{}, prefixes: map[string]string{}, blobs: map[string]Descriptor{}}
	var root *Descriptor
	for _, descriptor := range manifest.Layers {
		if !digestPattern.MatchString(descriptor.Digest) || descriptor.Size <= 0 || descriptor.Size >= blobLimit {
			return nil, errors.New("invalid catalog blob descriptor")
		}
		if prior, exists := view.reachable[descriptor.Digest]; exists && (prior.Size != descriptor.Size || prior.MediaType != descriptor.MediaType) {
			return nil, errors.New("conflicting snapshot blob descriptors")
		}
		view.reachable[descriptor.Digest] = descriptor
		if descriptor.Annotations[CatalogTitle] == "files" {
			if root != nil {
				return nil, errors.New("duplicate files catalog")
			}
			root = &descriptor
		}
	}
	if root == nil {
		return nil, errors.New("missing files catalog")
	}
	limit := CatalogLimit
	if root.MediaType == catalogRootMediaType {
		limit = catalogRootLimit
	}
	raw, err := readCatalogBlob(storage, repository, *root, identity, limit)
	if err != nil {
		return nil, err
	}
	var version struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
	}
	if err = json.Unmarshal(raw, &version); err != nil {
		return nil, err
	}
	if version.Format != SnapshotFormat {
		return nil, errors.New("unsupported catalog format")
	}
	switch version.Version {
	case 2:
		var catalog snapshotCatalog
		if err = json.Unmarshal(raw, &catalog); err != nil {
			return nil, err
		}
		if catalog.Files == nil || catalog.Narinfos == nil || catalog.Metadata == nil || catalog.Upstream == nil {
			return nil, errors.New("incomplete files catalog")
		}
		snapshot := NewSnapshot(storage, repository)
		snapshot.Manifest, snapshot.Digest = manifest, digest
		snapshot.Files, snapshot.Narinfos, snapshot.Metadata, snapshot.Upstream = catalog.Files, catalog.Narinfos, catalog.Metadata, catalog.Upstream
		if err = view.validateFiles(snapshot.Files); err != nil {
			return nil, err
		}
		if err = snapshot.ValidateRecords(); err != nil {
			return nil, err
		}
		view.legacy = snapshot
	case 3:
		if len(raw) > catalogRootLimit {
			return nil, errors.New("catalog root exceeds limit")
		}
		if err = json.Unmarshal(raw, &view.root); err != nil {
			return nil, err
		}
		if !digestPattern.MatchString(view.root.Recipients) {
			return nil, errors.New("invalid catalog recipient fingerprint")
		}
		for _, descriptor := range []Descriptor{view.root.Index, view.root.Writer, view.root.Metadata} {
			if err = view.reachableBlob(descriptor); err != nil {
				return nil, err
			}
		}
		view.blobs[contentDigest(raw)] = *root
	default:
		return nil, errors.New("unsupported catalog format")
	}
	return view, nil
}

func (v *catalogView) reachableBlob(descriptor Descriptor) error {
	target, exists := v.reachable[descriptor.Digest]
	if !exists || target.Size != descriptor.Size || target.MediaType != descriptor.MediaType {
		return errors.New("catalog references an unreachable blob")
	}
	return nil
}

func (v *catalogView) validateFiles(files map[string]SnapshotFile) error {
	for _, file := range files {
		if err := file.validate(); err != nil {
			return err
		}
		if err := v.reachableBlob(file.Blob); err != nil {
			return err
		}
	}
	return nil
}

func (v *catalogView) node(descriptor Descriptor, prefix string, consumer bool, identity Secret) (catalogNode, error) {
	if err := v.reachableBlob(descriptor); err != nil {
		return catalogNode{}, err
	}
	if prior, exists := v.prefixes[descriptor.Digest]; exists && prior != prefix {
		return catalogNode{}, errors.New("catalog node reused at a different prefix")
	}
	node, exists := v.nodes[descriptor.Digest]
	if !exists {
		raw, err := readCatalogBlob(v.storage, v.repository, descriptor, identity, catalogNodeLimit)
		if err != nil {
			return catalogNode{}, err
		}
		if err = json.Unmarshal(raw, &node); err != nil {
			return catalogNode{}, err
		}
		v.blobs[contentDigest(raw)] = descriptor
	}
	if len(prefix) > 64 || (node.Records == nil && len(node.Children) == 0) || (node.Records != nil && node.Children != nil) {
		return catalogNode{}, errors.New("invalid catalog tree")
	}
	for nibble, child := range node.Children {
		if len(nibble) != 1 || !strings.Contains("0123456789abcdef", nibble) || len(prefix) >= 64 {
			return catalogNode{}, errors.New("invalid catalog branch")
		}
		if err := v.reachableBlob(child); err != nil {
			return catalogNode{}, err
		}
	}
	for name, record := range node.Records {
		if (consumerFile(name) != consumer) || !strings.HasPrefix(strings.TrimPrefix(contentDigest([]byte(name)), "sha256:"), prefix) {
			return catalogNode{}, errors.New("invalid catalog record key")
		}
		if record.File == nil && record.Narinfo == "" && record.References == nil {
			return catalogNode{}, errors.New("empty catalog record")
		}
		if consumer && record.References != nil {
			return catalogNode{}, errors.New("upstream record in consumer catalog")
		}
		if !consumer && (record.Narinfo != "" || record.Archive != nil) {
			return catalogNode{}, errors.New("narinfo in writer catalog")
		}
		if record.References != nil {
			if !ValidStorePath(name) || *record.References == nil {
				return catalogNode{}, errors.New("invalid upstream coverage")
			}
			for _, ref := range *record.References {
				if !ValidStorePath(ref) {
					return catalogNode{}, errors.New("invalid upstream coverage")
				}
			}
		}
		if record.File != nil {
			if err := v.validateFiles(map[string]SnapshotFile{name: *record.File}); err != nil {
				return catalogNode{}, err
			}
		}
		if record.Narinfo != "" {
			fields, err := NarinfoFields(record.Narinfo)
			if err != nil {
				return catalogNode{}, err
			}
			if name != NarinfoKey(fields["StorePath"]) || record.Archive == nil {
				return catalogNode{}, errors.New("narinfo references an unreachable archive")
			}
			if err := v.validateFiles(map[string]SnapshotFile{name: *record.Archive}); err != nil {
				return catalogNode{}, err
			}
		} else if record.Archive != nil {
			return catalogNode{}, errors.New("archive without narinfo")
		}
	}
	v.nodes[descriptor.Digest] = node
	v.prefixes[descriptor.Digest] = prefix
	return node, nil
}

func addCatalogRecords(snapshot *Snapshot, records map[string]catalogRecord) error {
	addFile := func(name string, file SnapshotFile) error {
		if old, exists := snapshot.Files[name]; exists && (old.Blob.Digest != file.Blob.Digest || old.Offset != file.Offset || old.Size != file.Size || old.Digest != file.Digest) {
			return errors.New("conflicting catalog archive")
		}
		snapshot.Files[name] = file
		return nil
	}
	for name, record := range records {
		if record.File != nil {
			if err := addFile(name, *record.File); err != nil {
				return err
			}
		}
		if record.Narinfo != "" {
			fields, _ := NarinfoFields(record.Narinfo)
			if err := addFile("cache/"+fields["URL"], *record.Archive); err != nil {
				return err
			}
			snapshot.Narinfos[name] = record.Narinfo
		}
		if record.References != nil {
			snapshot.Upstream[name] = *record.References
		}
	}
	return nil
}

func (v *catalogView) lookup(name string, identity Secret) (*Snapshot, error) {
	if v.legacy != nil {
		return v.legacy, nil
	}
	snapshot := NewSnapshot(v.storage, v.repository)
	descriptor, prefix := v.root.Index, ""
	hash := strings.TrimPrefix(contentDigest([]byte(name)), "sha256:")
	for {
		node, err := v.node(descriptor, prefix, true, identity)
		if err != nil {
			return nil, err
		}
		if len(node.Children) == 0 {
			if err = addCatalogRecords(snapshot, node.Records); err != nil {
				return nil, err
			}
			return snapshot, nil
		}
		child, exists := node.Children[hash[len(prefix):len(prefix)+1]]
		if !exists {
			return snapshot, nil
		}
		prefix += hash[len(prefix) : len(prefix)+1]
		descriptor = child
	}
}

func (v *catalogView) loadAll(identity Secret) (*Snapshot, error) {
	if v.legacy != nil {
		return v.legacy, nil
	}
	snapshot := NewSnapshot(v.storage, v.repository)
	snapshot.Manifest, snapshot.Digest = v.manifest, v.digest
	var walk func(Descriptor, string, bool) error
	walk = func(descriptor Descriptor, prefix string, consumer bool) error {
		node, err := v.node(descriptor, prefix, consumer, identity)
		if err != nil {
			return err
		}
		if err = addCatalogRecords(snapshot, node.Records); err != nil {
			return err
		}
		for _, nibble := range sortedKeys(node.Children) {
			if err = walk(node.Children[nibble], prefix+nibble, consumer); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(v.root.Index, "", true); err != nil {
		return nil, err
	}
	if err := walk(v.root.Writer, "", false); err != nil {
		return nil, err
	}
	raw, err := readCatalogBlob(v.storage, v.repository, v.root.Metadata, identity, CatalogLimit)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &snapshot.Metadata); err != nil {
		return nil, err
	}
	if snapshot.Metadata == nil {
		return nil, errors.New("missing catalog metadata")
	}
	if err = snapshot.ValidateRecords(); err != nil {
		return nil, err
	}
	v.blobs[contentDigest(raw)] = v.root.Metadata
	snapshot.catalogBlobs, snapshot.catalogRecipients = v.blobs, v.root.Recipients
	return snapshot, nil
}
