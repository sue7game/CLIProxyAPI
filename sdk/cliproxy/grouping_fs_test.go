package cliproxy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGroupingFSSourceCreateAndReplace(t *testing.T) {
	dir := groupingFSTestDir(t)
	path := filepath.Join(dir, "source.json")
	before, after := []byte("old-test-content"), []byte("new-test-content")
	if err := writeGroupingSource(groupingFileChange{path: path, after: before}); err != nil {
		t.Fatal(err)
	}
	if err := writeGroupingSource(groupingFileChange{path: path, before: before, after: after}); err != nil {
		t.Fatal(err)
	}
	assertGroupingFSContent(t, path, after)
	assertGroupingFSOnlyEntries(t, dir, "source.json")
}

func TestGroupingFSExclusivePublishPreservesConcurrentWinner(t *testing.T) {
	dir := groupingFSTestDir(t)
	target := filepath.Join(dir, "source.json")
	name, err := prepareGroupingSourceTemp(target, []byte("loser"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeGroupingSource(groupingFileChange{path: target, after: []byte("winner")}); err != nil {
		t.Fatal(err)
	}
	if err := publishNewGroupingFile(name, target); err == nil {
		t.Fatal("exclusive publication overwrote a concurrent source")
	}
	assertGroupingFSContent(t, target, []byte("winner"))
	assertGroupingFSContent(t, name, []byte("loser"))
}

func TestGroupingFSConcurrentCreatesHaveOneWinner(t *testing.T) {
	dir := groupingFSTestDir(t)
	path := filepath.Join(dir, "source.json")
	start := make(chan struct{})
	winners := make(chan []byte, 8)
	var done sync.WaitGroup
	for index := range 8 {
		done.Go(func() {
			<-start
			data := []byte(fmt.Sprintf("test-source-%d", index))
			if err := writeGroupingSource(groupingFileChange{path: path, after: data}); err == nil {
				winners <- data
			}
		})
	}
	close(start)
	done.Wait()
	close(winners)
	var published [][]byte
	for winner := range winners {
		published = append(published, winner)
	}
	if len(published) != 1 {
		t.Fatalf("successful exclusive publications = %d, want 1", len(published))
	}
	assertGroupingFSContent(t, path, published[0])
	assertGroupingFSOnlyEntries(t, dir, "source.json")
}

func TestGroupingFSFailedReplaceKeepsTarget(t *testing.T) {
	dir := groupingFSTestDir(t)
	path := filepath.Join(dir, "source.json")
	if err := writeGroupingSource(groupingFileChange{path: path, after: []byte("existing")}); err != nil {
		t.Fatal(err)
	}
	if err := replaceGroupingFile(filepath.Join(dir, "missing"), path); err == nil {
		t.Fatal("missing replacement source was accepted")
	}
	assertGroupingFSContent(t, path, []byte("existing"))
}

func TestGroupingFSJournalRemovalIsExclusiveToRegularFiles(t *testing.T) {
	dir := groupingFSTestDir(t)
	path := filepath.Join(dir, "activation.pending")
	if err := writeGroupingSource(groupingFileChange{path: path, after: []byte("test-intent")}); err != nil {
		t.Fatal(err)
	}
	if err := removeGroupingFile(path); err != nil {
		t.Fatal(err)
	}
	assertGroupingFSOnlyEntries(t, dir)
	if err := removeGroupingFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing active journal error = %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := removeGroupingFile(path); err == nil {
		t.Fatal("journal removal accepted a directory")
	}
	assertGroupingFSOnlyEntries(t, dir, "activation.pending")
}

func groupingFSTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	protectGroupingFSTestDir(t, dir)
	return dir
}

func assertGroupingFSContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unexpected source contents: %v", err)
	}
}

func assertGroupingFSOnlyEntries(t *testing.T, path string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Fatalf("unexpected directory entries: got %d, want %d", len(entries), len(want))
	}
	for index, entry := range entries {
		if entry.Name() != want[index] {
			t.Fatalf("unexpected directory entry: %s", entry.Name())
		}
	}
}
