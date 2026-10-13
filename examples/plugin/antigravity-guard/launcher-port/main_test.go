package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePort(t *testing.T) {
	for _, test := range []struct {
		name string
		yaml string
		want int
	}{
		{"legacy", "port: 9001\n", 9001},
		{"block v8", "server:\n  port: 9002 # listener\n", 9002},
		{"flow v8", "server: {port: 9002}\n", 9002},
		{"quoted keys", "\"server\": {'port': 9002}\n", 9002},
		{"v8 first", "server: {port: 9002}\nport: 9001\n", 9002},
		{"legacy first", "port: 9001\nserver: {port: 9002}\n", 9002},
		{"legacy fallback", "port: 9001\nserver: {host: localhost}\n", 9001},
		{"missing", "server: {host: localhost}\n", 0},
		{"empty document", "", 0},
		{"null precedence", "port: 9001\nserver: {port: null}\n", 0},
		{"empty precedence", "port: 9001\nserver:\n  port:\n", 0},
		{"zero precedence", "port: 9001\nserver: {port: 0}\n", 0},
		{"legacy null", "port: null\n", 0},
		{"legacy zero", "port: 0\n", 0},
		{"nested unrelated port", "server: {host: localhost, extension: {port: 9999}}\n", 0},
		{"aliased server", "defaults: &listener {port: 9002}\nserver: *listener\n", 9002},
		{"aliased port", "default-port: &port 9002\nserver: {port: *port}\n", 9002},
		{"merged server", "defaults: &listener {port: 9002}\nserver: {<<: *listener}\n", 9002},
		{"explicit overrides merge", "defaults: &listener {port: 9002}\nserver: {<<: *listener, port: 9003}\n", 9003},
		{"root merge", "defaults: &root {server: {port: 9002}}\n<<: *root\n", 9002},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parsePort([]byte(test.yaml))
			if err != nil || got != test.want {
				t.Fatalf("parsePort() = %d, %v; want %d, nil", got, err, test.want)
			}
		})
	}
}

func TestParsePortRejectsInvalidConfiguration(t *testing.T) {
	for _, input := range []string{
		"server: [", "server: true", "server: null", "server: []",
		"port: 9001\nserver: {port: bad}", "server: {port: '9002'}",
		"port: 9001\nport: 9002", "server: {port: 9001, port: 9002}",
	} {
		if _, err := parsePort([]byte(input)); err == nil {
			t.Errorf("parsePort(%q) accepted invalid configuration", input)
		}
	}
}

func TestRunDoesNotRewriteConfigurationOrLoadCredentialPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := []byte("server: {port: 9002}\noauth: {auth-dir: /does/not/exist}\nmanagement: {secret-key: example}\n")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{path}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "9002\n" {
		t.Fatalf("output = %q, want 9002", output.String())
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(input, unchanged) {
		t.Fatalf("configuration changed: %v", err)
	}
}
