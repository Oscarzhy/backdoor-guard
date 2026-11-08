package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeCurrentProcessIdentity(t *testing.T) {
	identity, err := queryProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != os.Getpid() || !strings.EqualFold(filepath.Clean(expected), filepath.Clean(identity.Executable)) {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	created, err := time.Parse(time.RFC3339Nano, identity.CreationDate)
	if err != nil || created.After(time.Now().Add(time.Second)) {
		t.Fatalf("invalid creation time: %v %v", created, err)
	}
}

func TestWindowsPowerShellTemplates(t *testing.T) {
	shared := strings.ReplaceAll(powershellSessionLifecycleFunctions, "__EFFECTIVE_ACL_FUNCTIONS__", powershellEffectiveACLFunctions)
	watch := strings.ReplaceAll(watchdogScript, "__PERSISTENCE_FUNCTIONS__", shared)
	watch = strings.ReplaceAll(watch, "__JAVA_PROCESS_FUNCTIONS__", powershellJavaProcessFunctions)
	helper := strings.ReplaceAll(helperScript, "__PERSISTENCE_FUNCTIONS__", shared)
	helper = strings.ReplaceAll(helper, "__JAVA_PROCESS_FUNCTIONS__", powershellJavaProcessFunctions)
	helper = strings.ReplaceAll(helper, "__HELPER_WATCHDOG_FUNCTIONS__", powershellHelperWatchdogFunctions)
	helper = strings.ReplaceAll(helper, "__WATCHDOG_UTF16_B64__", psEncoded(watch))
	trampoline := buildUACTrampoline(`C:\test 中文\stage`, `C:\test 中文\stage\bootstrap.ps1`, strings.Repeat("0", 64), `C:\test 中文\diag.log`, "S-1-5-21-123")
	for name, source := range map[string]string{"watchdog": watch, "helper": helper, "trampoline": trampoline} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".ps1")
			if err := writeUTF8BOMFile(path, source, 0600); err != nil {
				t.Fatal(err)
			}
			if err := validatePowerShellScript(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}
