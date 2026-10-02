package keyvault

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ioflux-org/provisio/internal/state"
)

func ver(version, value string) secretVersion {
	return secretVersion{Version: version, Value: value, Enabled: true,
		Tags: map[string]string{"k": "v"}, Created: 100, Updated: 100}
}

// reopen builds a secret store over the journal in dir and replays it,
// as a restart does.
func reopen(t *testing.T, dir string) (*state.Log, *secretStore) {
	t.Helper()
	log, err := state.Open(dir, bytes.Repeat([]byte{1}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	st := newSecretStore(log)
	if err := log.Replay(); err != nil {
		t.Fatal(err)
	}
	return log, st
}

func TestSecretStoreLifecycle(t *testing.T) {
	st := newSecretStore(nil)
	s, v1, err := st.Set("KV", "Db-Pass", ver("v1", "one"))
	if err != nil || s.Name != "Db-Pass" || v1.Version != "v1" {
		t.Fatalf("first Set = %+v, %+v, %v", s, v1, err)
	}
	if _, v2, err := st.Set("kv", "db-pass", ver("v2", "two")); err != nil || v2.Version != "v2" {
		t.Fatalf("second Set = %+v, %v", v2, err)
	}

	s, got, err := st.Get("kv", "DB-PASS", "")
	if err != nil || got.Value != "two" || s.Name != "Db-Pass" || len(s.Versions) != 2 {
		t.Errorf("Get latest = %+v, %+v, %v; want value two, canonical name, 2 versions", s, got, err)
	}
	if _, got, err = st.Get("kv", "db-pass", "V1"); err != nil || got.Value != "one" {
		t.Errorf("Get by version (other casing) = %+v, %v", got, err)
	}
	if _, _, err = st.Get("kv", "db-pass", "nope"); !errors.Is(err, errVersionNotFound) {
		t.Errorf("Get unknown version: err = %v, want errVersionNotFound", err)
	}
	if _, _, err = st.Get("kv", "missing", ""); !errors.Is(err, errSecretNotFound) {
		t.Errorf("Get unknown secret: err = %v, want errSecretNotFound", err)
	}

	_, upd, err := st.Update("kv", "db-pass", "", func(v *secretVersion) {
		v.Enabled = false
		v.Updated = 200
	})
	if err != nil || upd.Enabled || upd.Updated != 200 {
		t.Errorf("Update = %+v, %v", upd, err)
	}
	if _, got, _ = st.Get("kv", "db-pass", ""); got.Enabled {
		t.Error("Update did not persist")
	}
	if live, _ := st.List("kv", false); len(live) != 1 {
		t.Errorf("List live = %d, want 1", len(live))
	}

	d, err := st.Delete("kv", "db-pass", 300)
	if err != nil || d.Deleted == nil || *d.Deleted != 300 {
		t.Fatalf("Delete = %+v, %v", d, err)
	}
	if _, _, err = st.Get("kv", "db-pass", ""); !errors.Is(err, errSecretNotFound) {
		t.Errorf("Get after Delete: err = %v, want errSecretNotFound", err)
	}
	if _, _, err = st.Set("kv", "db-pass", ver("v3", "three")); !errors.Is(err, errSecretDeleted) {
		t.Errorf("Set while deleted: err = %v, want errSecretDeleted", err)
	}
	if del, err := st.GetDeleted("kv", "db-pass"); err != nil || len(del.Versions) != 2 {
		t.Errorf("GetDeleted = %+v, %v", del, err)
	}
	deleted, _ := st.List("kv", true)
	live, _ := st.List("kv", false)
	if len(deleted) != 1 || len(live) != 0 {
		t.Errorf("after Delete: %d deleted, %d live; want 1, 0", len(deleted), len(live))
	}

	if r, err := st.Recover("kv", "db-pass"); err != nil || r.Deleted != nil {
		t.Fatalf("Recover = %+v, %v", r, err)
	}
	if _, _, err = st.Get("kv", "db-pass", ""); err != nil {
		t.Errorf("Get after Recover: %v", err)
	}
	if _, err = st.Recover("kv", "db-pass"); !errors.Is(err, errSecretNotFound) {
		t.Errorf("Recover a live secret: err = %v, want errSecretNotFound", err)
	}
	if err = st.Purge("kv", "db-pass"); !errors.Is(err, errSecretNotFound) {
		t.Errorf("Purge a live secret: err = %v, want errSecretNotFound", err)
	}
	st.Delete("kv", "db-pass", 400)
	if err = st.Purge("kv", "db-pass"); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err = st.GetDeleted("kv", "db-pass"); !errors.Is(err, errSecretNotFound) {
		t.Errorf("GetDeleted after Purge: err = %v", err)
	}
}

func TestSecretStoreCopiesOut(t *testing.T) {
	st := newSecretStore(nil)
	in := ver("v1", "one")
	st.Set("kv", "s", in)
	in.Tags["k"] = "changed"
	if _, got, _ := st.Get("kv", "s", ""); got.Tags["k"] != "v" {
		t.Error("Set shared memory with the caller")
	}
	_, got, _ := st.Get("kv", "s", "")
	got.Tags["k"] = "changed"
	if _, again, _ := st.Get("kv", "s", ""); again.Tags["k"] != "v" {
		t.Error("Get shared memory with the caller")
	}
	d, _ := st.Delete("kv", "s", 1)
	*d.Deleted = 999
	if dd, _ := st.GetDeleted("kv", "s"); *dd.Deleted != 1 {
		t.Error("Delete shared the Deleted pointer with the caller")
	}
}

func TestSecretStoreListSortedAndVaultsIsolated(t *testing.T) {
	st := newSecretStore(nil)
	for _, n := range []string{"beta", "Alpha", "gamma"} {
		st.Set("kv", n, ver("v", "x"))
	}
	st.Set("other", "zeta", ver("v", "x"))
	live, _ := st.List("kv", false)
	var names []string
	for _, s := range live {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "Alpha,beta,gamma" {
		t.Errorf("List = %v, want sorted case-insensitively", names)
	}
	st.DropVault("kv")
	if live, _ := st.List("kv", false); len(live) != 0 {
		t.Error("DropVault left secrets behind")
	}
	if other, _ := st.List("other", false); len(other) != 1 {
		t.Error("DropVault touched another vault")
	}
}

func TestSecretsSurviveReplay(t *testing.T) {
	dir := t.TempDir()
	log, st := reopen(t, dir)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := st.Set("KV", "Db-Pass", ver("v1", "one"))
	must(err)
	_, _, err = st.Set("kv", "db-pass", ver("v2", "two"))
	must(err)
	_, _, err = st.Update("kv", "db-pass", "v1", func(v *secretVersion) { v.Enabled = false })
	must(err)
	_, _, err = st.Set("kv", "gone", ver("v1", "x"))
	must(err)
	_, err = st.Delete("kv", "gone", 500)
	must(err)
	_, _, err = st.Set("kv", "purged", ver("v1", "x"))
	must(err)
	_, err = st.Delete("kv", "purged", 500)
	must(err)
	must(st.Purge("kv", "purged"))
	_, _, err = st.Set("other", "s", ver("v1", "x"))
	must(err)
	must(st.DropVault("other"))
	_, _, err = st.Set("kv", "only-set", ver("v1", "never touched again"))
	must(err)
	log.Close()

	log, st = reopen(t, dir)
	defer log.Close()
	s, v, err := st.Get("kv", "DB-PASS", "")
	if err != nil || s.Name != "Db-Pass" || len(s.Versions) != 2 || v.Value != "two" ||
		v.Tags["k"] != "v" || s.Versions[0].Enabled {
		t.Errorf("after replay: %+v, %+v, %v", s, v, err)
	}
	d, err := st.GetDeleted("kv", "gone")
	if err != nil || d.Deleted == nil || *d.Deleted != 500 {
		t.Errorf("soft-deleted secret after replay: %+v, %v", d, err)
	}
	if _, _, err := st.Get("kv", "purged", ""); !errors.Is(err, errSecretNotFound) {
		t.Errorf("purged secret must stay purged: %v", err)
	}
	if got, _ := st.List("other", false); len(got) != 0 {
		t.Errorf("dropped vault must stay empty: %+v", got)
	}
	_, v, err = st.Get("kv", "only-set", "")
	if err != nil || v.Value != "never touched again" {
		t.Errorf("a secret that was only Set must survive: %+v, %v", v, err)
	}
}
