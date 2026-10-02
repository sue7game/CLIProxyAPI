package grouping

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestStoreWriterProcessHelper(t *testing.T) {
	dir := os.Getenv("GROUPING_TEST_WRITER_DIRECTORY")
	if dir == "" {
		return
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	if _, err := fmt.Fprintln(os.Stdout, "writer-ready"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdin.Read(make([]byte, 1)); err != nil && err != io.EOF {
		t.Fatal(err)
	}
}

func TestStoreWriterLockRecoversAfterProcessExit(t *testing.T) {
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestStoreWriterProcessHelper$")
	command.Env = append(os.Environ(), "GROUPING_TEST_WRITER_DIRECTORY="+dir)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	}()
	ready := startPolicyWriter(t, command)
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("writer process did not become ready")
	}
	assertStoreCannotOpen(t, dir)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed writer unexpectedly exited cleanly")
	}
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	closeTestStore(t, reopened)
}

func startPolicyWriter(t *testing.T, command *exec.Cmd) <-chan error {
	t.Helper()
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			if err := command.Process.Kill(); err != nil {
				t.Error(err)
			}
			if err := command.Wait(); err == nil {
				t.Error("writer cleanup did not terminate child")
			}
		}
	})
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "writer-ready" {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- err
		} else {
			ready <- fmt.Errorf("writer output closed before readiness")
		}
	}()
	return ready
}
