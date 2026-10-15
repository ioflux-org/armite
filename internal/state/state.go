// Package state persists the emulator's mutable state across restarts:
// an append-only journal of sealed records plus a snapshot the journal
// is compacted into. Every record is one upsert or delete of one key in
// one store, so replaying a record twice is harmless - which is what
// makes crash recovery and compaction simple.
package state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// A Record is one change: the value of key in store, or its deletion.
type Record struct {
	Store   string          `json:"store"`
	Key     string          `json:"key"`
	Value   json.RawMessage `json:"value,omitempty"`
	Deleted bool            `json:"deleted,omitempty"`
}

// A Store can rebuild itself from records and dump itself for a
// snapshot. Restore is called during Replay, before the store serves;
// Dump is called during compaction, under whatever lock the store needs.
type Store interface {
	Restore(rec Record) error
	Dump(emit func(rec Record) error) error
}

const (
	journalName  = "journal"
	snapshotName = "snapshot"
	nonceSize    = 12
	maxRecord    = 64 << 20 // a length prefix beyond this is corruption, not data
)

// Log is the journal and its snapshot. A nil *Log is a valid,
// do-nothing Log, so stores work unchanged when persistence is off.
type Log struct {
	dir          string
	aead         cipher.AEAD
	compactAfter int64

	mu       sync.Mutex // guards journal, size, stores
	journal  *os.File
	size     int64
	stores   map[string]Store
	readOnly bool // opened by OpenReadOnly: never appends, truncates or compacts

	compactMu  sync.Mutex // one compaction at a time
	compacting bool
}

// Open prepares dir (created if missing) and its journal for appends.
// key is the 32-byte AES-256 key every record is sealed with. Nothing is
// read yet: attach the stores, then call Replay.
func Open(dir string, key []byte, compactAfter int64) (*Log, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, journalName), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return &Log{dir: dir, aead: aead, compactAfter: compactAfter, journal: f,
		size: info.Size(), stores: map[string]Store{}}, nil
}

// OpenReadOnly prepares an existing dir for Replay and nothing else:
// nothing is created, a torn tail is left for the server that owns the
// journal to cut, and Append fails. It is for a command that reads the
// state beside a running server, such as "armite hosts".
func OpenReadOnly(dir string, key []byte) (*Log, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Log{dir: dir, aead: aead, stores: map[string]Store{}, readOnly: true}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("state: key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return aead, nil
}

// Attach registers the store that owns records named name. Records for
// an unattached store are ignored on Replay and dropped by compaction.
func (l *Log) Attach(name string, s Store) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stores[name] = s
}

// Replay feeds every record of the snapshot, then of the journal, to
// its store. A torn record at the end of the journal - the mark of a
// crash mid-append - is cut off and logged; a record that fails to open
// anywhere else is corruption or the wrong key, and an error.
func (l *Log) Replay() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.replayFile(filepath.Join(l.dir, snapshotName), false); err != nil {
		return err
	}
	return l.replayFile(filepath.Join(l.dir, journalName), true)
}

func (l *Log) replayFile(path string, truncateTorn bool) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	good, err := l.apply(data)
	if err != nil {
		return fmt.Errorf("state: %s: %w", path, err)
	}
	if good < int64(len(data)) {
		if l.readOnly {
			return nil // the server owning the journal will cut the tail
		}
		if !truncateTorn {
			return fmt.Errorf("state: %s: torn record at byte %d", path, good)
		}
		log.Printf("state: journal has a torn record at byte %d of %d (crash mid-write); truncating",
			good, len(data))
		// By path, not through l.journal: that handle was opened for
		// appending, and on Windows an append-only handle may not change
		// the file's length. A second handle may — the journal's share
		// mode allows it — and the next append still lands at the new end.
		if err := os.Truncate(path, good); err != nil {
			return fmt.Errorf("state: %w", err)
		}
		l.size = good
	}
	return nil
}

// apply opens records in data one by one and hands them to their
// stores. It returns the offset just past the last complete record, so
// a torn tail can be recognised by the caller.
func (l *Log) apply(data []byte) (int64, error) {
	off := 0
	for off+4 <= len(data) {
		n := int(binary.BigEndian.Uint32(data[off:]))
		if n > maxRecord {
			return int64(off), fmt.Errorf("record length %d at byte %d is not credible", n, off)
		}
		if off+4+n > len(data) {
			break // torn
		}
		rec, err := l.open(data[off+4 : off+4+n])
		if err != nil {
			return int64(off), err
		}
		if s, ok := l.stores[rec.Store]; ok {
			if err := s.Restore(rec); err != nil {
				return int64(off), fmt.Errorf("store %s: %w", rec.Store, err)
			}
		}
		off += 4 + n
	}
	return int64(off), nil
}

// Append seals rec and writes it to the journal durably, then starts a
// compaction if the journal has outgrown its limit.
func (l *Log) Append(rec Record) error {
	if l == nil {
		return nil
	}
	if l.readOnly {
		return errors.New("state: opened read-only")
	}
	frame, err := l.seal(rec)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.journal.Write(frame); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := l.journal.Sync(); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	l.size += int64(len(frame))
	if l.compactAfter > 0 && l.size > l.compactAfter && !l.compacting {
		l.compacting = true
		go func() {
			if err := l.Compact(); err != nil {
				log.Printf("state: compaction: %v", err)
			}
		}()
	}
	return nil
}

// Compact writes every attached store's current records to a fresh
// snapshot and trims the journal to what was appended since the dump
// began. Records are idempotent, so the overlap between the dump and
// the kept tail is harmless. Appends continue throughout.
func (l *Log) Compact() error {
	if l == nil {
		return nil
	}
	l.compactMu.Lock()
	defer l.compactMu.Unlock()
	defer func() { l.mu.Lock(); l.compacting = false; l.mu.Unlock() }()

	l.mu.Lock()
	start := l.size
	stores := make(map[string]Store, len(l.stores))
	for k, v := range l.stores {
		stores[k] = v
	}
	l.mu.Unlock()

	tmp := filepath.Join(l.dir, snapshotName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	for _, s := range stores {
		err := s.Dump(func(rec Record) error {
			frame, err := l.seal(rec)
			if err != nil {
				return err
			}
			_, err = f.Write(frame)
			return err
		})
		if err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replace(tmp, filepath.Join(l.dir, snapshotName)); err != nil {
		return err
	}

	// Trim: keep only what was appended after the dump started.
	l.mu.Lock()
	defer l.mu.Unlock()
	tail := make([]byte, l.size-start)
	if _, err := l.journal.ReadAt(tail, start); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	jtmp := filepath.Join(l.dir, journalName+".tmp")
	if err := writeSynced(jtmp, tail); err != nil {
		return err
	}
	// Close before the rename: Windows will not replace a file that is
	// still open, and nothing can append while l.mu is held. Whatever
	// the rename did, reopen what is now at the journal's path.
	journal := filepath.Join(l.dir, journalName)
	l.journal.Close()
	renameErr := replace(jtmp, journal)
	l.journal, err = os.OpenFile(journal, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if renameErr != nil {
		return renameErr // the old journal is untouched and open again
	}
	l.size = int64(len(tail))
	return nil
}

// Close syncs and closes the journal.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.journal.Close()
}

// seal frames rec as length + nonce + ciphertext. GCM's tag makes any
// corruption of the frame detectable on open.
func (l *Log) seal(rec Record) ([]byte, error) {
	plain, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	body := l.aead.Seal(nonce, nonce, plain, nil)
	frame := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	return append(frame, body...), nil
}

func (l *Log) open(body []byte) (Record, error) {
	if len(body) < nonceSize {
		return Record{}, errors.New("record too short")
	}
	plain, err := l.aead.Open(nil, body[:nonceSize], body[nonceSize:], nil)
	if err != nil {
		return Record{}, errors.New("record cannot be opened: corrupted, or sealed with another key")
	}
	var rec Record
	if err := json.Unmarshal(plain, &rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// replace renames tmp over path and syncs the directory so the rename
// itself survives a crash. Rename is atomic on POSIX and on Windows;
// Windows cannot sync a directory handle, and does not need to.
func replace(tmp, path string) error {
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	return syncFile(filepath.Dir(path))
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// writeSynced writes data to path through a handle it can fsync.
// os.WriteFile followed by a sync through a read-only handle works on
// POSIX; Windows requires write access to flush a file.
func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
