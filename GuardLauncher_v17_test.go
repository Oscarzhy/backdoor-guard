package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndpointGrammar(t *testing.T) {
	cases := []struct {
		line, host string
		port       int
		ok         bool
	}{
		{"example.com:25565", "example.com", 25565, true}, {"login.live.com # auth", "login.live.com", 443, true},
		{"example.com.", "example.com", 443, true}, {"127.0.0.1:25565", "127.0.0.1", 25565, true},
		{"[::1]:25565", "::1", 25565, true}, {"::1", "::1", 443, true}, {"[::1]", "::1", 443, true},
		{"# comment", "", 0, false}, {"", "", 0, false}, {"*.example.com", "", 0, false}, {"Any", "", 0, false},
		{"https://example.com", "", 0, false}, {"example.com:0", "", 0, false}, {"example.com:65536", "", 0, false},
		{"bad..example:443", "", 0, false}, {"-bad.example", "", 0, false}, {"example.com junk", "", 0, false},
		{"example.com/path:443", "", 0, false}, {"example.com\\file:443", "", 0, false}, {"[garbage]:443", "", 0, false},
		{"例子.测试", "", 0, false}, {strings.Repeat("a", 64) + ".com", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			h, p, ok := parseLine(c.line)
			if ok != c.ok || ok && (h != c.host || p != c.port) {
				t.Fatalf("got (%q,%d,%t)", h, p, ok)
			}
		})
	}
}
func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestConfigurationBoundaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.txt")
	if _, err := readConfigText(path, false); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if text, err := readConfigText(path, true); err != nil || text != "" {
		t.Fatalf("%q %v", text, err)
	}
	for _, body := range [][]byte{[]byte("中文"), append([]byte{239, 187, 191}, []byte("中文")...)} {
		writeTestFile(t, path, body)
		text, err := readConfigText(path, false)
		if err != nil || text != "中文" {
			t.Fatalf("%q %v", text, err)
		}
	}
	for _, body := range [][]byte{{255, 254, 65, 0}, {195, 40}, []byte("a\x00b")} {
		writeTestFile(t, path, body)
		if _, err := readConfigText(path, true); err == nil {
			t.Fatal("accepted invalid encoding")
		}
	}
	if _, err := readConfigText(dir, true); err == nil {
		t.Fatal("directory treated as optional missing file")
	}
}
func TestProtectedPathsReadFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ProtectedPaths.txt")
	paths, err := readProtectedPaths(path)
	if err != nil || len(paths) != 4 {
		t.Fatalf("%v %v", paths, err)
	}
	writeTestFile(t, path, append([]byte{239, 187, 191}, []byte("# comment\nC:\\中文\\QQ\n")...))
	paths, err = readProtectedPaths(path)
	if err != nil || len(paths) != 5 || paths[4] != `C:\中文\QQ` {
		t.Fatalf("%v %v", paths, err)
	}
	if _, err := readProtectedPaths(dir); err == nil {
		t.Fatal("unreadable file silently defaulted")
	}
}
func TestEndpointDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AllowedDomains.txt")
	writeTestFile(t, path, []byte("127.0.0.1:443\nbad:0\n*.invalid:443\n# comment\n127.0.0.1:443\n"))
	endpoints, warnings, err := loadEndpoints(path)
	if err != nil || len(endpoints) != 1 || len(warnings) != 2 || !strings.Contains(warnings[0], "第 2 行") {
		t.Fatalf("%v %v %v", endpoints, warnings, err)
	}
}
func TestJavaDiscoveryAndExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"JAVA_HOME", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "PATH"} {
		t.Setenv(name, dir)
	}
	config := filepath.Join(dir, "JavaPaths.txt")
	launcher := filepath.Join(dir, "Launcher.exe")
	explicit := filepath.Join(dir, "configured", "java.exe")
	writeTestFile(t, explicit, []byte("fixture"))
	// More than five levels deep: scan exact runtime roots without the old cap.
	deep := filepath.Join(dir, "runtime", "a", "b", "c", "d", "e", "f", "g", "bin", "javaw.exe")
	writeTestFile(t, deep, []byte("fixture"))
	ide := filepath.Join(dir, "bin", "java.exe")
	writeTestFile(t, ide, []byte("fixture"))
	writeTestFile(t, config, append([]byte{239, 187, 191}, []byte(filepath.Join("configured", "java.exe")+"\n")...))
	result, err := loadJavaPaths(config, launcher)
	if err != nil || len(result.Paths) != 1 || result.Paths[0] != explicit || len(result.Candidates) != 1 || result.Candidates[0] != deep {
		t.Fatalf("%+v %v", result, err)
	}
	if result.Paths[0] == ide {
		t.Fatal("JAVA_HOME or PATH silently granted rules")
	}
	writeTestFile(t, config, []byte("does-not-exist.exe\n"))
	if _, err = loadJavaPaths(config, launcher); err == nil {
		t.Fatal("invalid explicit path ignored")
	}
	if _, err = loadJavaPaths(dir, launcher); err == nil {
		t.Fatal("unreadable config ignored")
	}
	if err = os.Remove(config); err != nil {
		t.Fatal(err)
	}
	result, err = loadJavaPaths(config, launcher)
	if err != nil || len(result.Paths) != 0 || len(result.Candidates) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestLauncherValidation(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "Launcher.EXE")
	writeTestFile(t, exe, []byte("fixture"))
	if got, err := validateLauncherPath(exe); err != nil || got != exe {
		t.Fatal(got, err)
	}
	text := filepath.Join(dir, "launcher.txt")
	writeTestFile(t, text, []byte("fixture"))
	for _, path := range []string{dir, text, filepath.Join(dir, "missing.exe")} {
		if _, err := validateLauncherPath(path); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
}
func TestNotificationTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notifications.ndjson")
	tail := notificationTail{}
	writeTestFile(t, path, append([]byte{239, 187, 191}, []byte("{\"recordId\":1}\n{\"recordId\":")...))
	lines, err := readNotificationLines(path, &tail)
	if err != nil || len(lines) != 1 {
		t.Fatal(lines, err)
	}
	var row map[string]int
	if err = json.Unmarshal([]byte(lines[0]), &row); err != nil || row["recordId"] != 1 {
		t.Fatal(lines, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("2}\n")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	lines, err = readNotificationLines(path, &tail)
	if err != nil || len(lines) != 1 || lines[0] != "{\"recordId\":2}" {
		t.Fatal(lines, err)
	}
	lines, err = readNotificationLines(path, &tail)
	if err != nil || len(lines) != 0 {
		t.Fatal("old lines reread", lines, err)
	}
	writeTestFile(t, path, []byte("{}\n"))
	lines, err = readNotificationLines(path, &tail)
	if err != nil || len(lines) != 1 {
		t.Fatal("truncate", lines, err)
	}
	replacement := path + ".new"
	writeTestFile(t, replacement, []byte("{\"recordId\":3}\n"))
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	lines, err = readNotificationLines(path, &tail)
	if err != nil || len(lines) != 1 || !strings.Contains(lines[0], "3") {
		t.Fatal("replace", lines, err)
	}
	// A pathological partial line is bounded and discarded through its newline.
	writeTestFile(t, path, append(bytes.Repeat([]byte{'x'}, 70*1024), []byte("\n{}\n")...))
	tail = notificationTail{}
	lines, err = readNotificationLines(path, &tail)
	if err != nil || len(lines) != 1 || lines[0] != "{}" {
		t.Fatal("oversize", lines, err)
	}
}
