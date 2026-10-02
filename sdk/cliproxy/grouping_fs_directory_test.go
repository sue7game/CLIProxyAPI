package cliproxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGroupingFSDirectoryPublication(t *testing.T) {
	dir := groupingFSTestDir(t)
	stage, target := filepath.Join(dir, "stage"), filepath.Join(dir, "policy")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeGroupingSource(groupingFileChange{path: filepath.Join(stage, "policy.json"), after: []byte("complete-test-policy")}); err != nil {
		t.Fatal(err)
	}
	if err := publishGroupingDirectory(stage, target); err != nil {
		t.Fatal(err)
	}
	assertGroupingFSContent(t, filepath.Join(target, "policy.json"), []byte("complete-test-policy"))
	assertGroupingFSOnlyEntries(t, dir, "policy")
}

func TestGroupingFSDirectoryPublicationRejectsExistingTarget(t *testing.T) {
	for _, populated := range []bool{false, true} {
		name := "empty"
		if populated {
			name = "complete"
		}
		t.Run(name, func(t *testing.T) {
			dir := groupingFSTestDir(t)
			stage, target := filepath.Join(dir, "stage"), filepath.Join(dir, "policy")
			for _, path := range []string{stage, target} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if populated {
				if err := writeGroupingSource(groupingFileChange{path: filepath.Join(target, "policy.json"), after: []byte("existing-policy")}); err != nil {
					t.Fatal(err)
				}
			}
			if err := publishGroupingDirectory(stage, target); err == nil {
				t.Fatal("directory publication overwrote an existing installation path")
			}
			assertGroupingFSOnlyEntries(t, dir, "policy", "stage")
			if populated {
				assertGroupingFSContent(t, filepath.Join(target, "policy.json"), []byte("existing-policy"))
			}
		})
	}
}
