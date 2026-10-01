package state

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// memStore is the simplest Store: a map of key to raw JSON value.
type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newMem() *memStore { return &memStore{m: map[string]string{}} }

func (s *memStore) Restore(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.Deleted {
		delete(s.m, rec.Key)
	} else {
		s.m[rec.Key] = string(rec.Value)
	}
	return nil
}

func (s *memStore) Dump(emit func(Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if err := emit(Record{Store: "t", Key: k, Value: json.RawMessage(v)}); err != nil {
			return err
		}
	}
	return nil
}

var testKey = bytes.Repeat([]byte{7}, 32)

func open(t *testing.T, dir string, key []byte, compactAfter int64) (*Log, *memStore) {
	t.Helper()
	l, err := Open(dir, key, compactAfter)
	if err != nil {
		t.Fatal(err)
	}
	s := newMem()
	l.Attach("t", s)
	if err := l.Replay(); err != nil {
		t.Fatal(err)
	}
	return l, s
}

// put mutates the store AND appends the record, in that order, the way
// a real store does: the in-memory state is the truth compaction dumps,
// the journal is how it survives a restart.
func put(t *testing.T, l *Log, s *memStore, key, value string) {
	t.Helper()
	rec := Record{Store: "t", Key: key, Value: json.RawMessage(value)}
	s.Restore(rec)
	if err := l.Append(rec); err != nil {
		t.Fatal(err)
	}
}

func del(t *testing.T, l *Log, s *memStore, key string) {
	t.Helper()
	rec := Record{Store: "t", Key: key, Deleted: true}
	s.Restore(rec)
	if err := l.Append(rec); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, s := open(t, dir, testKey, 0)
	put(t, l, s, "a", `"1"`)
	put(t, l, s, "b", `"2"`)
	put(t, l, s, "a", `"3"`)
	del(t, l, s, "b")
	if err := l.Append(Record{Store: "other", Key: "x", Value: json.RawMessage(`1`)}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	_, s = open(t, dir, testKey, 0)
	if len(s.m) != 1 || s.m["a"] != `"3"` {
		t.Errorf("after replay: %v, want a=3 only (upsert, delete, unattached store ignored)", s.m)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, journalName))
	if bytes.Contains(raw, []byte(`"a"`)) || bytes.Contains(raw, []byte("other")) {
		t.Error("the journal must not contain plaintext")
	}
}

func TestTornTailIsCutOff(t *testing.T) {
	dir := t.TempDir()
	l, s := open(t, dir, testKey, 0)
	put(t, l, s, "a", `"1"`)
	put(t, l, s, "b", `"2"`)
	l.Close()
	path := filepath.Join(dir, journalName)
	raw, _ := os.ReadFile(path)
	// cut the last record in half: a crash mid-append
	if err := os.WriteFile(path, raw[:len(raw)-10], 0o600); err != nil {
		t.Fatal(err)
	}

	l, s = open(t, dir, testKey, 0)
	if len(s.m) != 1 || s.m["a"] != `"1"` {
		t.Errorf("after torn tail: %v, want a only", s.m)
	}
	put(t, l, s, "c", `"3"`) // appends after the cut, not after the garbage
	l.Close()
	_, s = open(t, dir, testKey, 0)
	if len(s.m) != 2 || s.m["c"] != `"3"` {
		t.Errorf("after append past the cut: %v, want a and c", s.m)
	}
}

func TestCorruptionAndWrongKeyAreErrors(t *testing.T) {
	dir := t.TempDir()
	l, s := open(t, dir, testKey, 0)
	put(t, l, s, "a", `"1"`)
	put(t, l, s, "b", `"2"`)
	l.Close()
	path := filepath.Join(dir, journalName)
	raw, _ := os.ReadFile(path)

	l2, err := Open(dir, bytes.Repeat([]byte{9}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	l2.Attach("t", newMem())
	if err := l2.Replay(); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Errorf("wrong key: err = %v", err)
	}
	l2.Close()

	flipped := append([]byte{}, raw...)
	flipped[4+nonceSize+2] ^= 0xff // inside the first record's ciphertext
	os.WriteFile(path, flipped, 0o600)
	l3, _ := Open(dir, testKey, 0)
	l3.Attach("t", newMem())
	if err := l3.Replay(); err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Errorf("mid-file corruption must be an error, not a silent cut: %v", err)
	}
	l3.Close()

	huge := append([]byte{}, raw...)
	binary.BigEndian.PutUint32(huge, 1<<30)
	os.WriteFile(path, huge, 0o600)
	l4, _ := Open(dir, testKey, 0)
	l4.Attach("t", newMem())
	if err := l4.Replay(); err == nil || !strings.Contains(err.Error(), "not credible") {
		t.Errorf("absurd length must be an error: %v", err)
	}
	l4.Close()
}

func TestCompactionKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	l, s := open(t, dir, testKey, 0)
	for i := range 200 {
		put(t, l, s, fmt.Sprintf("k%d", i), fmt.Sprintf(`"v%d"`, i))
	}
	for i := 0; i < 200; i += 2 {
		del(t, l, s, fmt.Sprintf("k%d", i))
	}
	before, _ := os.Stat(filepath.Join(dir, journalName))

	// Appends that race the compaction must survive it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			put(t, l, s, fmt.Sprintf("late%d", i), `"x"`)
		}
	}()
	if err := l.Compact(); err != nil {
		t.Fatal(err)
	}
	<-done
	l.Close()

	after, _ := os.Stat(filepath.Join(dir, journalName))
	snap, err := os.Stat(filepath.Join(dir, snapshotName))
	if err != nil || snap.Size() == 0 || after.Size() >= before.Size() {
		t.Errorf("snapshot %v, journal before %d after %d", err, before.Size(), after.Size())
	}
	_, s2 := open(t, dir, testKey, 0)
	if len(s2.m) != 150 || s2.m["k1"] != `"v1"` || s2.m["late49"] != `"x"` {
		t.Errorf("after compaction + replay: %d keys, want 150 (100 odd + 50 late)", len(s2.m))
	}
}

func TestAutomaticCompactionTriggers(t *testing.T) {
	dir := t.TempDir()
	l, s := open(t, dir, testKey, 2000)
	for i := range 100 {
		put(t, l, s, fmt.Sprintf("k%d", i), `"v"`)
	}
	// The background compaction holds compactMu; taking it waits for it.
	l.compactMu.Lock()
	l.compactMu.Unlock()
	if _, err := os.Stat(filepath.Join(dir, snapshotName)); err != nil {
		t.Errorf("a journal past compact_after must have produced a snapshot: %v", err)
	}
	l.Close()
	_, s2 := open(t, dir, testKey, 2000)
	if len(s2.m) != 100 {
		t.Errorf("after automatic compaction: %d keys, want 100", len(s2.m))
	}
}

func TestNilLogIsANoOp(t *testing.T) {
	var l *Log
	l.Attach("t", newMem())
	if err := l.Replay(); err != nil {
		t.Error(err)
	}
	if err := l.Append(Record{Store: "t", Key: "k"}); err != nil {
		t.Error(err)
	}
	if err := l.Compact(); err != nil {
		t.Error(err)
	}
	if err := l.Close(); err != nil {
		t.Error(err)
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadKey(dir, "")
	if err != nil || len(k1) != 32 {
		t.Fatalf("LoadKey generated = %d bytes, %v", len(k1), err)
	}
	info, _ := os.Stat(filepath.Join(dir, keyName))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}
	k2, _ := LoadKey(dir, "")
	if !bytes.Equal(k1, k2) {
		t.Error("the generated key must be stable across calls")
	}
	conf := strings.Repeat("A", 43) + "=" // 32 zero bytes, base64
	k3, err := LoadKey(dir, conf)
	if err != nil || bytes.Equal(k3, k1) {
		t.Errorf("configured key must win: %v", err)
	}
	if _, err := LoadKey(dir, "short"); err == nil {
		t.Error("a bad configured key must fail")
	}
}
