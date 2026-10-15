// Package azurite runs the Azurite blob service that backs the storage
// data plane in managed mode: one child process, started with the
// accounts Armite knows and restarted when that set changes, because
// Azurite reads its accounts from the environment at start-up only.
package azurite

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager owns the process. Safe for concurrent use; Start and Stop
// serialize.
type Manager struct {
	command  string
	location string
	port     int

	mu       sync.Mutex
	proc     *exec.Cmd
	exited   chan error // receives the exit error once proc ends
	accounts map[string]string
}

// New prepares a manager for command (azurite-blob, resolved on PATH),
// keeping its data under location and listening on 127.0.0.1:port.
func New(command, location string, port int) *Manager {
	return &Manager{command: command, location: location, port: port}
}

// Addr is where the service listens.
func (m *Manager) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.port)
}

// Start launches Azurite knowing exactly accounts (name to base64 key),
// replacing a running instance whose set differs, and returns once the
// port answers. A running instance with the same accounts is kept.
func (m *Manager) Start(accounts map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc != nil && maps.Equal(m.accounts, accounts) {
		return nil
	}
	if err := m.stopLocked(); err != nil {
		return err
	}
	if err := m.waitFree(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.location, 0o700); err != nil {
		return fmt.Errorf("azurite: %w", err)
	}
	cmd := exec.Command(m.command,
		"--location", m.location,
		"--blobHost", "127.0.0.1",
		"--blobPort", fmt.Sprint(m.port),
		"--skipApiVersionCheck", // newer SDKs send versions Azurite does not know yet
		"--silent",              // no per-request access log on stdout
		"--disableTelemetry",
	)
	cmd.Env = append(os.Environ(), "AZURITE_ACCOUNTS="+accountsEnv(accounts))
	dieWithParent(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("azurite: %w", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("azurite: starting %s: %w", m.command, err)
	}
	go relay(out)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	if err := m.waitReady(exited); err != nil {
		return err
	}
	m.proc, m.exited = cmd, exited
	m.accounts = maps.Clone(accounts)
	log.Printf("azurite: serving %d account(s) on %s (data in %s)",
		len(accounts), m.Addr(), m.location)
	return nil
}

// waitReady polls the port until Azurite accepts connections, or the
// process ends, or 20 seconds pass.
func (m *Manager) waitReady(exited <-chan error) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			return fmt.Errorf("azurite: exited during start-up: %v", err)
		default:
		}
		conn, err := net.DialTimeout("tcp", m.Addr(), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("azurite: did not start listening within 20s")
}

// waitFree gives a just-ended Azurite a moment to release the port and
// refuses to start while something else holds it: waitReady would greet
// that stranger and every storage request would go to it.
func (m *Manager) waitFree() error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", m.Addr(), 200*time.Millisecond)
		if err != nil {
			return nil // nothing listens
		}
		conn.Close()
		if time.Now().After(deadline) {
			return fmt.Errorf("azurite: %s is already in use (an Azurite from an earlier run? end it, or set azurite.port)", m.Addr())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Stop ends the process: on POSIX politely first, so Azurite flushes
// its metadata database, and by force after five seconds; on Windows
// the whole process tree at once, since no signal can reach it.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

func (m *Manager) stopLocked() error {
	if m.proc == nil {
		return nil
	}
	proc, exited := m.proc, m.exited
	m.proc, m.exited = nil, nil
	interrupt(proc)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = proc.Process.Kill()
		<-exited
	}
	return nil
}

// accountsEnv renders AZURITE_ACCOUNTS: "name1:key1;name2:key2", sorted
// so the value is stable. With no accounts Azurite would fall back to
// its built-in devstoreaccount1 and its public key; a placeholder with
// a random key keeps that door shut.
func accountsEnv(accounts map[string]string) string {
	if len(accounts) == 0 {
		key := make([]byte, 64)
		rand.Read(key)
		return "placeholder:" + base64.StdEncoding.EncodeToString(key)
	}
	names := make([]string, 0, len(accounts))
	for name := range accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+":"+accounts[name])
	}
	return strings.Join(parts, ";")
}

// relay copies the child's output to the log, one line at a time, so
// Azurite's start-up lines and complaints appear next to Armite's.
func relay(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		log.Printf("azurite: %s", sc.Text())
	}
}
