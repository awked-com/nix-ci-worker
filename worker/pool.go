package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const RunnersPerSystem = 3
const poolStartupTimeout = 10 * time.Minute
const poolLease = 5 * time.Minute
const poolPoll = 2 * time.Second
const poolHeartbeat = time.Minute

var regexpRun = regexp.MustCompile(`^[0-9]+$`)

type poolTask struct {
	Cores       int      `json:"cores"`
	Installable string   `json:"installable"`
	BuildInputs []string `json:"buildInputs"`
	Inputs      string   `json:"inputs"`
	PublicKey   string   `json:"publicKey"`
	Outputs     []string `json:"outputs"`
}

type poolMessage struct {
	Cores    int       `json:"cores,omitempty"`
	Finish   []uint64  `json:"finish,omitempty"`
	Session  string    `json:"session"`
	Instance string    `json:"instance,omitempty"`
	Sequence uint64    `json:"sequence"`
	State    string    `json:"state"`
	Sent     time.Time `json:"sent"`
	Features []string  `json:"features,omitempty"`
	Task     *poolTask `json:"task,omitempty"`
	Snapshot string    `json:"snapshot,omitempty"`
}

type poolEnvelope struct {
	Data []byte `json:"data"`
	MAC  string `json:"mac"`
}

type poolRecord struct {
	digest string
	data   []byte
}

type poolReads struct {
	sync.Mutex
	records map[string]poolRecord
}

type poolBus struct {
	controlRecipients       Secret
	storage                 Storage
	control                 Storage
	repository, run, system string
	attempt                 int
	identity, recipients    Secret
	key                     []byte
	close                   func()
	reads                   *poolReads
}

func newPoolBus(storage Storage, repository, run, system string, attempt int, identity, recipients Secret, binding any) (*poolBus, error) {
	if _, ok := Systems[system]; !ok || attempt < 1 || !regexpRun.MatchString(run) {
		return nil, errors.New("invalid builder pool")
	}
	if len(identity.Data) == 0 {
		return nil, errors.New("missing builder identity")
	}
	raw, err := json.Marshal([]any{"infra-ci-registry-pool-1", repository, run, system, attempt, binding})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, identity.Data)
	mac.Write(raw)
	b := &poolBus{storage: storage, control: storage, repository: repository, run: run, system: system, attempt: attempt, identity: identity, recipients: recipients, key: mac.Sum(nil), close: func() {}}
	b.reads = &poolReads{records: map[string]poolRecord{}}
	// Lease traffic must not wait behind large NAR uploads or their retry budget.
	if registry, ok := storage.(*Registry); ok {
		control := NewRegistry(registry.auth)
		control.repositoryAuth = registry.repositoryAuth
		control.HTTP.Timeout, control.UploadHTTP.Timeout = 30*time.Second, 30*time.Second
		control.uploadRetries = 2
		b.control, b.close = control, control.Close
	}
	controlRecipients, err := IdentityRecipients(identity)
	if err != nil {
		b.close()
		return nil, err
	}
	b.controlRecipients = controlRecipients
	return b, nil
}

func poolNonce() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}

func (b *poolBus) tag(role string, runner int) string {
	return fmt.Sprintf("nixos-cache-pool-%s-%d-%s-%s-%d", b.run, b.attempt, b.system, role, runner)
}

func (b *poolBus) controlRepository() string {
	return b.repository + "-pool"
}

func (b *poolBus) authenticate(tag string, data []byte) []byte {
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte(tag + "\x00"))
	mac.Write(data)
	return mac.Sum(nil)
}

func (b *poolBus) write(role string, runner int, message poolMessage) error {
	message.Sent = time.Now().UTC()
	raw, err := json.Marshal(message)
	if err != nil {
		return err
	}
	tag := b.tag(role, runner)
	snapshot := NewSnapshot(b.control, b.controlRepository())
	snapshot.Metadata = map[string]any{"kind": "control", "run": b.run, "message": poolEnvelope{raw, hex.EncodeToString(b.authenticate(tag, raw))}}
	_, err = snapshot.publish(tag, b.controlRecipients, b.repository)
	return err
}

func (b *poolBus) read(role string, runner int) (*poolMessage, error) {
	tag := b.tag(role, runner)
	manifest, digest, err := b.control.GetManifest(b.controlRepository(), tag)
	if err != nil {
		return nil, err
	}
	b.reads.Lock()
	record := b.reads.records[tag]
	b.reads.Unlock()
	// Poll the tag for changes without downloading unchanged catalogs again.
	// Keep the original Sent timestamp so cached reads cannot extend a lease.
	if record.digest != digest {
		snapshot, err := loadSnapshot(b.control, b.controlRepository(), manifest, digest, b.identity)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(snapshot.Metadata["message"])
		var envelope poolEnvelope
		if err == nil {
			err = json.Unmarshal(raw, &envelope)
		}
		if err != nil {
			return nil, errors.New("invalid pool envelope")
		}
		signature, err := hex.DecodeString(envelope.MAC)
		if err != nil || !hmac.Equal(signature, b.authenticate(tag, envelope.Data)) {
			return nil, errors.New("pool message authentication failed")
		}
		record = poolRecord{digest, envelope.Data}
		b.reads.Lock()
		b.reads.records[tag] = record
		b.reads.Unlock()
	}
	var message poolMessage
	if err := json.Unmarshal(record.data, &message); err != nil {
		return nil, errors.New("invalid pool message")
	}
	return &message, nil
}

func poolFresh(message *poolMessage, lease time.Duration) bool {
	return message != nil && time.Since(message.Sent) < lease && time.Until(message.Sent) < time.Minute
}

func (b *poolBus) signingKey(runner int) Secret {
	name := fmt.Sprint(runner)
	key := ed25519.NewKeyFromSeed(b.authenticate("transport-signing", []byte(name)))
	return Secret{Data: []byte("infra-ci-transfer-" + name + ":" + base64.StdEncoding.EncodeToString(key))}
}

// Every helper has one assignment writer and one status writer. A new assignment
// acknowledges the previous result; publishing or reading a record twice is safe.
type BuildPool struct {
	cpus     int
	timing   poolTiming
	finish   atomic.Pointer[[RunnersPerSystem]uint64]
	wake     chan struct{}
	bus      *poolBus
	session  string
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stop     atomic.Bool
	statuses [RunnersPerSystem]atomic.Pointer[poolMessage]
	changed  [RunnersPerSystem]chan struct{}
	log      io.Writer
}

func StartBuildPool(bus *poolBus, log io.Writer) *BuildPool {
	return startBuildPool(bus, log, productionPoolTiming)
}

func startBuildPool(bus *poolBus, log io.Writer, timing poolTiming) *BuildPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &BuildPool{cpus: runtime.NumCPU(), timing: timing, bus: bus, session: poolNonce(), wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel, log: log}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(timing.heartbeat)
		defer ticker.Stop()
		for {
			state := "running"
			if p.stop.Load() {
				state = "stop"
			}
			message := poolMessage{Session: p.session, State: state}
			if finish := p.finish.Load(); finish != nil {
				message.Finish = append([]uint64{}, finish[:]...)
			}
			if err := bus.write("coordinator", 0, message); err != nil {
				fmt.Fprintln(log, "warning: coordinator lease publication failed; retrying")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-p.wake:
			}
		}
	}()
	for runner := 1; runner < RunnersPerSystem; runner++ {
		p.changed[runner] = make(chan struct{}, 1)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			ticker := time.NewTicker(timing.poll)
			defer ticker.Stop()
			for {
				message, err := bus.read("status", runner)
				if err == nil && message.Session == p.session {
					previous := p.statuses[runner].Load()
					if previous == nil || message.Sent.After(previous.Sent) {
						p.statuses[runner].Store(message)
						select {
						case p.changed[runner] <- struct{}{}:
						default:
						}
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	return p
}

func (p *BuildPool) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (p *BuildPool) Drain() { p.stop.Store(true); p.notify() }

func (p *BuildPool) Close() {
	p.cancel()
	p.wg.Wait()
	if err := p.bus.write("coordinator", 0, poolMessage{Session: p.session, State: "stop"}); err != nil {
		fmt.Fprintln(p.log, "warning: builder shutdown publication failed; helpers will expire their leases")
	}
	p.bus.close()
}

func validFeatures(features []string) bool {
	for _, feature := range features {
		if !nativeName.MatchString(feature) {
			return false
		}
	}
	return true
}
