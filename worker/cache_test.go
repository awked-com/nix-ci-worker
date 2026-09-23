package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const cacheTestRepository = "ghcr.io/test/infra-ci"

type memoryCache struct {
	mu        sync.Mutex
	objects   map[string][]byte
	manifests map[string][]byte
	tags      map[string]string
	failure   error
	gets      int
}

func newMemoryCache() *memoryCache {
	return &memoryCache{
		objects:   map[string][]byte{},
		manifests: map[string][]byte{},
		tags:      map[string]string{},
	}
}

func (m *memoryCache) UploadBlob(repository string, source io.Reader, encrypted bool) (Descriptor, error) {
	data, err := io.ReadAll(source)
	if err != nil {
		return Descriptor{}, err
	}
	if encrypted && !bytes.HasPrefix(data, []byte("age-encryption.org/v1\n")) {
		return Descriptor{}, errors.New("unencrypted test object")
	}

	d := Descriptor{
		Digest:    contentDigest(data),
		Size:      int64(len(data)),
		MediaType: "application/octet-stream",
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.objects[d.Digest] = data
	return d, nil
}

func (m *memoryCache) Blob(repository string, d Descriptor) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.gets++
	if m.failure != nil {
		return nil, m.failure
	}

	data, ok := m.objects[d.Digest]
	if !ok {
		return nil, ErrObjectNotFound
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *memoryCache) BlobRange(repository string, file SnapshotFile) (io.ReadCloser, error) {
	if err := file.validate(); err != nil {
		return nil, err
	}
	source, err := m.Blob(repository, file.Blob)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	data, err := io.ReadAll(source)
	if err != nil {
		return nil, err
	}
	if file.Offset+file.Size > int64(len(data)) {
		return nil, io.ErrUnexpectedEOF
	}
	return &verifiedBlob{
		source:     io.NopCloser(bytes.NewReader(data[file.Offset : file.Offset+file.Size])),
		descriptor: Descriptor{Digest: file.Digest, Size: file.Size},
		checksum:   sha256.New(),
	}, nil
}

func (m *memoryCache) PutManifest(repository, tag string, manifest Manifest) (string, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}

	digest := contentDigest(data)
	m.mu.Lock()
	defer m.mu.Unlock()

	m.manifests[digest] = data
	m.tags[tag] = digest
	return digest, nil
}

func (m *memoryCache) GetManifest(repository, reference string) (Manifest, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failure != nil {
		return Manifest{}, "", m.failure
	}

	digest := reference
	if !strings.HasPrefix(reference, "sha256:") {
		digest = m.tags[reference]
	}

	data, ok := m.manifests[digest]
	if !ok {
		return Manifest{}, "", ErrObjectNotFound
	}

	var manifest Manifest
	err := json.Unmarshal(data, &manifest)
	return manifest, digest, err
}

func cacheKeys(t *testing.T) (Secret, Secret) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return Secret{Data: []byte(identity.String() + "\n")}, Secret{Data: []byte(identity.Recipient().String() + "\n")}
}

func cacheRecord(snapshot *Snapshot, char string, references ...string) string {
	path := "/nix/store/" + strings.Repeat(char, 32) + "-private-package"
	archive := "nar/" + strings.Repeat(char, 64) + ".nar.zst"
	snapshot.Files["cache/"+archive] = wholeFile(Descriptor{
		Digest:    "sha256:" + strings.Repeat(char, 64),
		Size:      3,
		MediaType: "application/octet-stream",
	})
	snapshot.Narinfos[NarinfoKey(path)] = fmt.Sprintf(
		"StorePath: %s\nURL: %s\nCompression: zstd\nNarHash: sha256:abc\nNarSize: 3\nReferences: %s\nSig: test:signature\n",
		path,
		archive,
		strings.Join(references, " "),
	)
	return path
}

func cacheAdd(snapshot *Snapshot, name string, source io.Reader, recipients Secret) error {
	packer := newNARPacker(snapshot, recipients)
	if err := packer.add(name, source); err != nil {
		return err
	}
	return packer.finish()
}

func cacheRead(t *testing.T, snapshot *Snapshot, name string, identity Secret) []byte {
	t.Helper()
	reader, err := snapshot.Read(name, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func cachePublish(t *testing.T, snapshot *Snapshot, tag string, recipients Secret) string {
	t.Helper()
	digest, err := snapshot.Publish(tag, recipients)
	if err != nil {
		t.Fatal(err)
	}

	return digest
}

func cacheLoad(t *testing.T, storage Storage, reference string, identity Secret) *Snapshot {
	t.Helper()
	snapshot, err := LoadSnapshot(storage, cacheTestRepository, reference, identity)
	if err != nil {
		t.Fatal(err)
	}

	return snapshot
}

func TestSnapshotEncryptedCatalog(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	snapshot.Metadata["source"] = "private-source"
	path := cacheRecord(snapshot, "a")
	if err := cacheAdd(snapshot, "cache/nar/"+strings.Repeat("a", 64)+".nar.zst", strings.NewReader("NAR"), recipients); err != nil {
		t.Fatal(err)
	}

	cachePublish(t, snapshot, PlatformTag("aarch64-linux"), recipients)
	loaded := cacheLoad(t, storage, PlatformTag("aarch64-linux"), identity)
	if !reflect.DeepEqual(loaded.Narinfos, snapshot.Narinfos) || !reflect.DeepEqual(loaded.Metadata, snapshot.Metadata) {
		t.Fatal("snapshot content changed")
	}
	for _, layer := range loaded.Manifest.Layers {
		if title := layer.Annotations[CatalogTitle]; title != "" && title != "files" {
			t.Fatalf("unexpected catalog %q", title)
		}
	}

	before := storage.gets
	if got := string(cacheRead(t, loaded, NarinfoKey(path), identity)); !strings.Contains(got, path) {
		t.Fatal(got)
	}

	if storage.gets != before {
		t.Fatal("inline record required a blob read")
	}

	for _, data := range storage.manifests {
		for _, secret := range []string{"private-package", "StorePath", "private-source"} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("public manifest leaked %q", secret)
			}
		}
	}

	for _, data := range storage.objects {
		if !bytes.Equal(data, []byte("{}")) && !bytes.HasPrefix(data, []byte("age-encryption.org/v1\n")) {
			t.Fatal("plaintext object")
		}
	}

	manifest := snapshot.Manifest
	manifest.Layers = append([]Descriptor{}, manifest.Layers...)
	for i, layer := range manifest.Layers {
		if layer.Annotations[CatalogTitle] != "files" {
			manifest.Layers[i].Annotations = map[string]string{CatalogTitle: "archive"}
		}
	}
	if _, err := storage.PutManifest(cacheTestRepository, "annotated", manifest); err != nil {
		t.Fatal(err)
	}
	loaded = cacheLoad(t, storage, "annotated", identity)
	if !reflect.DeepEqual(loaded.Files, snapshot.Files) || !reflect.DeepEqual(loaded.Metadata, snapshot.Metadata) {
		t.Fatal("payload annotations changed snapshot content")
	}
	if got := string(cacheRead(t, loaded, "cache/nar/"+strings.Repeat("a", 64)+".nar.zst", identity)); got != "NAR" {
		t.Fatal(got)
	}

	child := NewSnapshot(storage, cacheTestRepository)
	if err := child.Merge(loaded); err != nil {
		t.Fatal(err)
	}

	cachePublish(t, child, "next", recipients)
	if !reflect.DeepEqual(child.Files, loaded.Files) {
		t.Fatal("merge lost ciphertext")
	}
}

func TestSnapshotRequiresOneFilesCatalog(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	cachePublish(t, snapshot, "latest", recipients)
	var catalog Descriptor
	for _, layer := range snapshot.Manifest.Layers {
		if layer.Annotations[CatalogTitle] == "files" {
			catalog = layer
		}
	}
	for _, titles := range [][]string{
		{},
		{"unknown"},
		{"files", "files"},
	} {
		t.Run(fmt.Sprint(titles), func(t *testing.T) {
			manifest := snapshot.Manifest
			manifest.Layers = nil
			for _, title := range titles {
				layer := catalog
				layer.Annotations = map[string]string{CatalogTitle: title}
				manifest.Layers = append(manifest.Layers, layer)
			}
			digest, err := storage.PutManifest(cacheTestRepository, "invalid", manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = LoadSnapshot(storage, cacheTestRepository, digest, identity); err == nil {
				t.Fatal("accepted invalid snapshot catalogs")
			}
		})
	}
}

func TestSnapshotClosureAndMergeValidation(t *testing.T) {
	snapshot := NewSnapshot(newMemoryCache(), cacheTestRepository)
	a := cacheRecord(snapshot, "a", strings.Repeat("b", 32)+"-private-package")
	if err := snapshot.RequireClosed(); err == nil || !strings.Contains(err.Error(), "incomplete references") {
		t.Fatal(err)
	}

	b := cacheRecord(snapshot, "b", strings.Repeat("a", 32)+"-private-package")
	if err := snapshot.RequireClosed(); err != nil {
		t.Fatal(err)
	}

	conflicting := NewSnapshot(snapshot.Storage, snapshot.Repository)
	cacheRecord(conflicting, "a")
	conflicting.Narinfos[NarinfoKey(a)] = strings.ReplaceAll(conflicting.Narinfos[NarinfoKey(a)], "NarSize: 3", "NarSize: 4")
	if err := snapshot.Merge(conflicting); err == nil {
		t.Fatal("accepted conflicting NAR")
	}

	snapshot.Upstream[a] = []string{b}
	snapshot.Upstream[b] = []string{}

	if err := snapshot.RequireClosed(); err != nil {
		t.Fatal(err)
	}

	snapshot.Upstream[b] = []string{"/nix/store/" + strings.Repeat("c", 32) + "-missing"}
	if err := snapshot.RequireClosed(); err == nil {
		t.Fatal("upstream hid dangling reference")
	}
}

func TestSnapshotRejectsUnreachableCatalogAndCorruptCiphertext(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	packer := newNARPacker(snapshot, recipients)
	for _, char := range []string{"a", "b"} {
		cacheRecord(snapshot, char)
		if err := packer.add("cache/nar/"+strings.Repeat(char, 64)+".nar.zst", strings.NewReader("NAR")); err != nil {
			t.Fatal(err)
		}
	}
	if err := packer.finish(); err != nil {
		t.Fatal(err)
	}

	cachePublish(t, snapshot, "latest", recipients)
	manifest := snapshot.Manifest
	layers := []Descriptor{}
	for _, layer := range manifest.Layers {
		if layer.Annotations[CatalogTitle] != "" {
			layers = append(layers, layer)
		}
	}

	manifest.Layers = layers
	digest, err := storage.PutManifest(cacheTestRepository, "broken", manifest)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = LoadSnapshot(storage, cacheTestRepository, digest, identity); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatal(err)
	}

	for _, layer := range snapshot.Manifest.Layers {
		if layer.Annotations[CatalogTitle] == "files" {
			data := storage.objects[layer.Digest]
			storage.objects[layer.Digest] = data[:len(data)-1]
		}
	}

	if _, err = LoadSnapshot(storage, cacheTestRepository, "latest", identity); err == nil {
		t.Fatal("accepted truncated ciphertext")
	}
}

func TestSnapshotReaderRefreshPinningAndRecovery(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	path := cacheRecord(snapshot, "a")
	name := NarinfoKey(path)
	first := cachePublish(t, snapshot, PlatformTag("aarch64-linux"), recipients)
	reader := NewSnapshotReader(storage, cacheTestRepository, "", identity, nil)
	now := time.Unix(1000, 0)

	reader.now = func() time.Time { return now }

	original, err := reader.Current(name)
	if err != nil || original.Digest != first {
		t.Fatal(err)
	}

	pinned := NewSnapshotReader(storage, cacheTestRepository, first, identity, nil)
	if _, err = pinned.Current(name); err != nil {
		t.Fatal(err)
	}

	snapshot.Metadata["change"] = true
	second := cachePublish(t, snapshot, PlatformTag("aarch64-linux"), recipients)
	cached, err := reader.Current(name)
	if err != nil || cached.Digest != first {
		t.Fatal("refreshed too early", err)
	}

	now = now.Add(31 * time.Second)
	storage.failure = errors.New("GHCR unavailable")
	cached, err = reader.Current(name)
	if err != nil || cached.Digest != first {
		t.Fatal("lost existing catalog", err)
	}

	if _, err = reader.Current("missing"); err == nil {
		t.Fatal("missing path suppressed refresh failure")
	}

	storage.failure = nil
	now = now.Add(5 * time.Second)
	updated, err := reader.Current(name)
	if err != nil || updated.Digest != second {
		t.Fatal("did not recover", err)
	}

	still, err := pinned.Current(name)
	if err != nil || still.Digest != first {
		t.Fatal("pinned reference changed", err)
	}
}

func TestCacheHandlerHonorsPinnedReference(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	first := NewSnapshot(storage, cacheTestRepository)
	firstPath := cacheRecord(first, "a")
	firstDigest := cachePublish(t, first, PlatformTag("aarch64-linux"), recipients)

	latest := NewSnapshot(storage, cacheTestRepository)
	latestPath := cacheRecord(latest, "b")
	cachePublish(t, latest, PlatformTag("aarch64-linux"), recipients)

	handler := NewCacheHandler(storage, cacheTestRepository, firstDigest, identity, nil)
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := http.Get(server.URL + "/" + strings.TrimPrefix(NarinfoKey(firstPath), "cache/"))
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), firstPath) {
		t.Fatal("pinned cache record unavailable", response.StatusCode, readErr)
	}

	response, err = http.Get(server.URL + "/" + strings.TrimPrefix(NarinfoKey(latestPath), "cache/"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("handler followed latest instead of its pinned reference", response.StatusCode)
	}
}

func TestFileCacheHandlerReloadsIdentity(t *testing.T) {
	oldIdentity, oldRecipients := cacheKeys(t)
	newIdentity, newRecipients := cacheKeys(t)
	identityPath := filepath.Join(t.TempDir(), "identity")
	replaceIdentity := func(data []byte) {
		t.Helper()
		replacement := identityPath + ".new"
		if err := os.WriteFile(replacement, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, identityPath); err != nil {
			t.Fatal(err)
		}
	}
	replaceIdentity(oldIdentity.Data)

	storage := newMemoryCache()
	oldSnapshot := NewSnapshot(storage, cacheTestRepository)
	oldName := "cache/nar/old.nar.zst"
	oldPayload := []byte("old private payload")
	if err := cacheAdd(oldSnapshot, oldName, bytes.NewReader(oldPayload), oldRecipients); err != nil {
		t.Fatal(err)
	}
	cachePublish(t, oldSnapshot, PlatformTag("aarch64-linux"), oldRecipients)

	handler := NewFileCacheHandler(storage, cacheTestRepository, "", identityPath, nil)
	now := time.Unix(1000, 0)
	handler.reader.now = func() time.Time { return now }
	server := httptest.NewServer(handler)
	defer server.Close()
	get := func(name string) (int, []byte) {
		t.Helper()
		response, err := server.Client().Get(server.URL + "/" + strings.TrimPrefix(name, "cache/"))
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return response.StatusCode, body
	}

	if status, body := get(oldName); status != http.StatusOK || !bytes.Equal(body, oldPayload) {
		t.Fatalf("initial identity: status %d body %q", status, body)
	}

	newSnapshot := NewSnapshot(storage, cacheTestRepository)
	newName := "cache/nar/" + strings.Repeat("b", 64) + ".nar.zst"
	newPayload := []byte("new private payload")
	if err := cacheAdd(newSnapshot, newName, bytes.NewReader(newPayload), newRecipients); err != nil {
		t.Fatal(err)
	}
	storePath := "/nix/store/" + strings.Repeat("a", 32) + "-private-package"
	narinfoName := NarinfoKey(storePath)
	narinfo := "StorePath: " + storePath + "\nURL: " + strings.TrimPrefix(newName, "cache/") + "\nCompression: zstd\nNarHash: sha256:abc\nNarSize: 3\nReferences: \nSig: test:signature\n"
	newSnapshot.Narinfos[narinfoName] = narinfo
	// Catalogs can contain both entries; cached narinfo takes precedence.
	newSnapshot.Files[narinfoName] = newSnapshot.Files[newName]
	cachePublish(t, newSnapshot, PlatformTag("aarch64-linux"), newRecipients)
	combined := append(append([]byte{}, oldIdentity.Data...), newIdentity.Data...)
	replaceIdentity(combined)
	now = now.Add(31 * time.Second)

	if status, body := get(newName); status != http.StatusOK || !bytes.Equal(body, newPayload) {
		t.Fatalf("rotated identity: status %d body %q", status, body)
	}

	replaceIdentity([]byte("invalid age identity\n"))
	if status, _ := get(newName); status != http.StatusBadGateway {
		t.Fatalf("invalid replacement served encrypted data: status %d", status)
	}

	if err := os.Remove(identityPath); err != nil {
		t.Fatal(err)
	}
	if status, _ := get(newName); status != http.StatusBadGateway {
		t.Fatalf("unreadable replacement served encrypted data: status %d", status)
	}
	if status, body := get(narinfoName); status != http.StatusOK || string(body) != narinfo {
		t.Fatalf("cached metadata required an identity: status %d body %q", status, body)
	}
}

type slowManifestStorage struct {
	Storage
	started, release chan struct{}
}

func (s slowManifestStorage) GetManifest(repo, ref string) (Manifest, string, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}

	<-s.release
	return s.Storage.GetManifest(repo, ref)
}

func (s slowManifestStorage) ManifestDigest(repo, ref string) (string, error) {
	_, digest, err := s.GetManifest(repo, ref)
	return digest, err
}

func TestSlowRefreshServesExistingPaths(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	name := NarinfoKey(cacheRecord(snapshot, "a"))
	cachePublish(t, snapshot, PlatformTag("aarch64-linux"), recipients)
	reader := NewSnapshotReader(storage, cacheTestRepository, "", identity, nil)
	original, err := reader.Current(name)
	if err != nil {
		t.Fatal(err)
	}

	reader.deadline = time.Time{}
	started, release := make(chan struct{}, 1), make(chan struct{})
	reader.storage = slowManifestStorage{storage, started, release}
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader.Current("")
	}()
	<-started
	result := make(chan *Snapshot, 1)
	go func() {
		s, _ := reader.Current(name)
		result <- s
	}()
	select {
	case current := <-result:
		if current != original {
			t.Fatal("changed catalog")
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("existing path blocked")
	}

	close(release)
	<-done
}

func TestCacheHTTPMetadataPathsAndEncryptedRoundTrip(t *testing.T) {
	identity, recipients := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	payload := bytes.Repeat([]byte("private-package"), 15000)
	name := "cache/nar/payload.nar.zst"
	if err := cacheAdd(snapshot, name, bytes.NewReader(payload), recipients); err != nil {
		t.Fatal(err)
	}

	handler := NewCacheHandler(storage, "", "", identity, nil)
	handler.SetSnapshot(snapshot)
	server := httptest.NewServer(handler)
	defer server.Close()

	for _, method := range []string{"GET", "HEAD"} {
		request, _ := http.NewRequest(method, server.URL+"/nix-cache-info", nil)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}

		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || response.ContentLength != 38 {
			t.Fatalf("metadata %d %d %s %v", response.StatusCode, response.ContentLength, body, err)
		}
	}

	for _, path := range []string{
		"/../identity",
		"/%2e%2e/identity",
		"/logs/anything",
		"/nix-cache-info?x=1",
		"/nar/missing.nar.zst",
	} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}

		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatalf("%s: %d", path, response.StatusCode)
		}
	}

	response, err := server.Client().Get(server.URL + "/nar/payload.nar.zst")
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("round trip: %v", err)
	}

	request, _ := http.NewRequest("HEAD", server.URL+"/nar/payload.nar.zst", nil)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}

	storage.failure = errors.New("access denied")
	response, err = server.Client().Get(server.URL + "/nar/payload.nar.zst")
	if err != nil {
		t.Fatal(err)
	}

	response.Body.Close()
	if response.StatusCode != 502 || len(handler.Errors()) != 1 {
		t.Fatal("cache failure hidden")
	}
}

func TestCacheHTTPRejectsWrongIdentityAndIncompleteCiphertext(t *testing.T) {
	identity, recipients := cacheKeys(t)
	other, _ := cacheKeys(t)
	storage := newMemoryCache()
	snapshot := NewSnapshot(storage, cacheTestRepository)
	name := "cache/nar/payload.nar.zst"
	payload := bytes.Repeat([]byte("payload"), 30000)
	if err := cacheAdd(snapshot, name, bytes.NewReader(payload), recipients); err != nil {
		t.Fatal(err)
	}

	wrongHandler := NewCacheHandler(storage, "", "", other, nil)
	wrongHandler.SetSnapshot(snapshot)
	wrong := httptest.NewServer(wrongHandler)
	response, err := wrong.Client().Get(wrong.URL + "/nar/payload.nar.zst")
	if err != nil {
		t.Fatal(err)
	}

	response.Body.Close()
	wrong.Close()
	if response.StatusCode != 502 {
		t.Fatal("wrong identity accepted")
	}

	descriptor := snapshot.Files[name]
	data := storage.objects[descriptor.Digest]
	data[len(data)-1] ^= 1
	handler := NewCacheHandler(storage, "", "", identity, nil)
	handler.SetSnapshot(snapshot)
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err = server.Client().Get(server.URL + "/nar/payload.nar.zst")
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err == nil || response.StatusCode != 200 {
		t.Fatalf("corrupt stream silently succeeded: status %d err %v", response.StatusCode, err)
	}
}

func TestSnapshotDescriptorRequiresDeclaredIntegerSize(t *testing.T) {
	for _, raw := range []string{
		`{"digest":"sha256:abc"}`,
		`{"digest":"sha256:abc","size":null}`,
		`{"digest":"sha256:abc","size":true}`,
		`{"digest":"sha256:abc","size":1.5}`,
	} {
		var descriptor Descriptor
		if err := json.Unmarshal([]byte(raw), &descriptor); err == nil {
			t.Fatalf("accepted undeclared or invalid size: %s", raw)
		}
	}
}

func TestProcessCancellationPropagates(t *testing.T) {
	stream, err := ProcessStream([]string{"sh", "-c", "printf started; exec sleep 30"}, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	first := make([]byte, 7)
	if _, err = io.ReadFull(stream, first); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		stream.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not cancel its subprocess")
	}
}

func TestEncryptedStreamPropagatesSourceFailure(t *testing.T) {
	_, recipients := cacheKeys(t)
	source, writer := io.Pipe()
	stream, err := EncryptedStream(source, recipients)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	failure := errors.New("source interrupted")
	go func() {
		writer.Write([]byte("partial payload"))
		writer.CloseWithError(failure)
	}()
	if _, err = io.ReadAll(stream); !errors.Is(err, failure) {
		t.Fatalf("source failure lost: %v", err)
	}
}

func TestAgeStreamCancellationClosesSource(t *testing.T) {
	identity, recipients := cacheKeys(t)
	for _, decrypt := range []bool{false, true} {
		t.Run(fmt.Sprintf("decrypt=%v", decrypt), func(t *testing.T) {
			source, writer := io.Pipe()
			defer writer.Close()
			var stream io.ReadCloser
			var err error
			if decrypt {
				stream, err = decryptedStream(source, identity)
			} else {
				stream, err = EncryptedStream(source, recipients)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { stream.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled age stream left its producer blocked")
			}
			if _, err = writer.Write([]byte("data")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("source was not closed: %v", err)
			}
		})
	}
}

func TestIdentityRecipientsPreservesNativeKeyTypes(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	credential := Secret{Data: []byte("# generated keys\n" + x.String() + "\n\n" + pq.String() + "\n")}
	recipients, err := IdentityRecipients(credential)
	if err != nil {
		t.Fatal(err)
	}
	want := x.Recipient().String() + "\n" + pq.Recipient().String() + "\n"
	if string(recipients.Data) != want {
		t.Fatalf("wrong public recipients: %s", recipients.Data)
	}
}

func TestReadCredentialFileLoadsAndRedactsSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, []byte("private value"), 0600); err != nil {
		t.Fatal(err)
	}
	secret, err := ReadCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data) != "private value" || fmt.Sprintf("%v %#v", secret, secret) != "[secret] [secret]" {
		t.Fatal("credential file contents were not kept as a redacted in-memory secret")
	}
	if err = os.WriteFile(path, bytes.Repeat([]byte("x"), credentialLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadCredentialFile(path); err == nil {
		t.Fatal("oversized credential accepted")
	}
}

func TestCredentialPipePassesSecretWithoutAFile(t *testing.T) {
	secret := Secret{Data: []byte("private value")}
	err := withCredential(secret, func(path string, files []*os.File) error {
		if path != "/dev/fd/3" || len(files) != 1 {
			return errors.New("invalid credential descriptor")
		}
		data, err := io.ReadAll(files[0])
		if err != nil {
			return err
		}
		if !bytes.Equal(data, secret.Data) {
			return errors.New("credential contents changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := errors.New("command failed")
	if err = withCredential(Secret{Data: bytes.Repeat([]byte("x"), credentialLimit)}, func(string, []*os.File) error {
		return want
	}); !errors.Is(err, want) {
		t.Fatalf("callback failure lost: %v", err)
	}
}

func (s *memoryCache) ManifestDigest(repository, reference string) (string, error) {
	_, digest, err := s.GetManifest(repository, reference)
	return digest, err
}
