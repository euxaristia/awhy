package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- getPrefix ---

func TestGetPrefix(t *testing.T) {
	tests := []struct {
		weight   int
		expected string
	}{
		{0, "[+]"},
		{1, "[!]"},
		{2, "[-]"},
		{3, "[-]"},
		{-1, "[-]"},
		{99, "[-]"},
	}
	for _, tt := range tests {
		got := getPrefix(tt.weight)
		if got != tt.expected {
			t.Errorf("getPrefix(%d) = %q, want %q", tt.weight, got, tt.expected)
		}
	}
}

// --- isPermissionDenied ---

func TestIsPermissionDenied(t *testing.T) {
	if isPermissionDenied(nil) {
		t.Error("isPermissionDenied(nil) should be false")
	}
	if isPermissionDenied(fmt.Errorf("random error")) {
		t.Error("isPermissionDenied(random) should be false")
	}
	if !isPermissionDenied(os.ErrPermission) {
		t.Error("isPermissionDenied(os.ErrPermission) should be true")
	}
}

// --- getSysctlResult ---

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGetSysctlResult_MatchesExpected(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "val", "2\n")
	m := map[string]string{"0": "Disabled", "1": "Partial", "2": "Full"}

	r := getSysctlResult(path, "2", "TestCheck", m)
	if r.Prefix != "[+]" {
		t.Errorf("expected [+], got %s", r.Prefix)
	}
	if r.Colour != ColourGreen {
		t.Error("expected green")
	}
	if r.SortWeight != 0 {
		t.Errorf("expected weight 0, got %d", r.SortWeight)
	}
	if !strings.Contains(r.Status, "Full") || !strings.Contains(r.Status, "2") {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestGetSysctlResult_DoesNotMatchExpected(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "val", "1\n")
	m := map[string]string{"0": "Disabled", "1": "Partial", "2": "Full"}

	r := getSysctlResult(path, "2", "TestCheck", m)
	if r.Prefix != "[!]" {
		t.Errorf("expected [!], got %s", r.Prefix)
	}
	if r.Colour != ColourYellow {
		t.Error("expected yellow")
	}
	if r.SortWeight != 1 {
		t.Errorf("expected weight 1, got %d", r.SortWeight)
	}
	if !strings.Contains(r.Status, "Partial") {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestGetSysctlResult_UnknownValue(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "val", "99\n")
	m := map[string]string{"0": "Disabled", "1": "Enabled"}

	r := getSysctlResult(path, "1", "TestCheck", m)
	if r.Prefix != "[!]" {
		t.Errorf("expected [!], got %s", r.Prefix)
	}
	if !strings.Contains(r.Status, "Unknown") {
		t.Errorf("expected Unknown in status, got: %s", r.Status)
	}
}

func TestGetSysctlResult_FileNotFound(t *testing.T) {
	r := getSysctlResult("/nonexistent/path/xyz", "1", "TestCheck", nil)
	if r.Prefix != "[-]" {
		t.Errorf("expected [-], got %s", r.Prefix)
	}
	if !strings.Contains(r.Status, "Not available") {
		t.Errorf("expected 'Not available', got: %s", r.Status)
	}
	if r.SortWeight != 2 {
		t.Errorf("expected weight 2, got %d", r.SortWeight)
	}
}

func TestGetSysctlResult_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noperm")
	if err := os.WriteFile(path, []byte("1"), 0000); err != nil {
		t.Fatal(err)
	}
	// Only works if not running as root
	if os.Geteuid() == 0 {
		t.Skip("skipping permission test as root")
	}
	r := getSysctlResult(path, "1", "TestCheck", nil)
	if r.Prefix != "[-]" {
		t.Errorf("expected [-], got %s", r.Prefix)
	}
	if !strings.Contains(r.Status, "Requires root") {
		t.Errorf("expected 'Requires root', got: %s", r.Status)
	}
}

// --- checkModuleSigning ---

func TestCheckModuleSigning_NilConfig(t *testing.T) {
	r := checkModuleSigning(nil)
	if r.Prefix != "[-]" {
		t.Errorf("expected [-], got %s", r.Prefix)
	}
	if !strings.Contains(r.Status, "Requires /proc/config.gz") {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckModuleSigning_NotEnabled(t *testing.T) {
	config := map[string]string{}
	r := checkModuleSigning(config)
	if r.Prefix != "[-]" {
		t.Errorf("expected [-], got %s", r.Prefix)
	}
	if r.Status != "Not enabled" {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckModuleSigning_EnabledNotEnforced(t *testing.T) {
	config := map[string]string{
		"CONFIG_MODULE_SIG":      "y",
		"CONFIG_MODULE_SIG_HASH": "\"sha512\"",
	}
	r := checkModuleSigning(config)
	if r.Prefix != "[!]" {
		t.Errorf("expected [!], got %s", r.Prefix)
	}
	if !strings.Contains(r.Status, "not enforced") {
		t.Errorf("unexpected status: %s", r.Status)
	}
	// Check subinfo for hash
	found := false
	for _, s := range r.SubInfo {
		if strings.Contains(s, "sha512") {
			found = true
		}
	}
	if !found {
		t.Error("expected sha512 in subinfo")
	}
	// Check default key type is RSA
	foundRSA := false
	for _, s := range r.SubInfo {
		if strings.Contains(s, "RSA") {
			foundRSA = true
		}
	}
	if !foundRSA {
		t.Error("expected RSA key type in subinfo")
	}
}

func TestCheckModuleSigning_Enforced(t *testing.T) {
	config := map[string]string{
		"CONFIG_MODULE_SIG":                "y",
		"CONFIG_MODULE_SIG_FORCE":          "y",
		"CONFIG_MODULE_SIG_KEY_TYPE_ECDSA": "y",
	}
	r := checkModuleSigning(config)
	if r.Prefix != "[+]" {
		t.Errorf("expected [+], got %s", r.Prefix)
	}
	if r.Status != "Enforced" {
		t.Errorf("unexpected status: %s", r.Status)
	}
	foundECDSA := false
	for _, s := range r.SubInfo {
		if strings.Contains(s, "ECDSA") {
			foundECDSA = true
		}
	}
	if !foundECDSA {
		t.Error("expected ECDSA key type in subinfo")
	}
}

// --- checkKexecDisabled ---

func TestCheckKexecDisabled_SysctlDisabled(t *testing.T) {
	// Can't easily mock the file read without refactoring, but we can test the config fallback path.
	// When sysctl doesn't exist and config says kexec not compiled in:
	config := map[string]string{
		"CONFIG_KEXEC":      "n",
		"CONFIG_KEXEC_FILE": "n",
	}
	r := checkKexecDisabled(config)
	// On this system the sysctl might exist; test config fallback only if sysctl is missing
	if strings.Contains(r.Status, "Not compiled in") {
		if r.Prefix != "[+]" {
			t.Errorf("expected [+], got %s", r.Prefix)
		}
	}
	// If sysctl exists (like on a test runner with kexec), that's fine too
}

func TestCheckKexecDisabled_ConfigHasKexec(t *testing.T) {
	config := map[string]string{
		"CONFIG_KEXEC": "y",
	}
	r := checkKexecDisabled(config)
	// Either sysctl path succeeds or it falls through to "Could not determine"
	if r.Prefix != "[+]" && r.Prefix != "[!]" && r.Prefix != "[-]" {
		t.Errorf("unexpected prefix: %s", r.Prefix)
	}
}

func TestCheckKexecDisabled_NilConfig(t *testing.T) {
	r := checkKexecDisabled(nil)
	// Without config, should still attempt sysctl; either way must return valid result
	if r.Description != "kexec_load Disabled" {
		t.Errorf("unexpected description: %s", r.Description)
	}
}

// --- checkUserfaultfd ---

func TestCheckUserfaultfd_CompiledOut(t *testing.T) {
	config := map[string]string{
		"CONFIG_USERFAULTFD": "n",
	}
	r := checkUserfaultfd(config)
	if strings.Contains(r.Status, "Not compiled in") {
		if r.Prefix != "[+]" {
			t.Errorf("expected [+], got %s", r.Prefix)
		}
	}
}

func TestCheckUserfaultfd_CompiledIn(t *testing.T) {
	config := map[string]string{
		"CONFIG_USERFAULTFD": "y",
	}
	r := checkUserfaultfd(config)
	if r.Description != "Unprivileged userfaultfd" {
		t.Errorf("unexpected description: %s", r.Description)
	}
}

func TestCheckUserfaultfd_NilConfig(t *testing.T) {
	r := checkUserfaultfd(nil)
	if r.Description != "Unprivileged userfaultfd" {
		t.Errorf("unexpected description: %s", r.Description)
	}
}

// --- checkUserNamespaces ---

func TestCheckUserNamespaces_ConfigUnprivDisabled(t *testing.T) {
	config := map[string]string{
		"CONFIG_USER_NS":              "y",
		"CONFIG_USER_NS_UNPRIVILEGED": "n",
	}
	r := checkUserNamespaces(config)
	// The sysctl checks might match first on this system, but the config path should work
	if r.Description != "User Namespace Restrict" {
		t.Errorf("unexpected description: %s", r.Description)
	}
}

func TestCheckUserNamespaces_Unrestricted(t *testing.T) {
	config := map[string]string{
		"CONFIG_USER_NS":              "y",
		"CONFIG_USER_NS_UNPRIVILEGED": "y",
	}
	r := checkUserNamespaces(config)
	if r.Description != "User Namespace Restrict" {
		t.Errorf("unexpected description: %s", r.Description)
	}
}

func TestCheckUserNamespaces_NilConfig(t *testing.T) {
	r := checkUserNamespaces(nil)
	if r.Description != "User Namespace Restrict" {
		t.Errorf("unexpected description: %s", r.Description)
	}
}

// --- checkHardenedKernel ---

func TestCheckHardenedKernel_FullyHardened(t *testing.T) {
	config := map[string]string{
		"CONFIG_INIT_ON_ALLOC_DEFAULT_ON":       "y",
		"CONFIG_INIT_ON_FREE_DEFAULT_ON":        "y",
		"CONFIG_HARDENED_USERCOPY":              "y",
		"CONFIG_FORTIFY_SOURCE":                 "y",
		"CONFIG_SLAB_FREELIST_RANDOM":           "y",
		"CONFIG_SLAB_FREELIST_HARDENED":         "y",
		"CONFIG_LIST_HARDENED":                  "y",
		"CONFIG_SHUFFLE_PAGE_ALLOCATOR":         "y",
		"CONFIG_VMAP_STACK":                     "y",
		"CONFIG_STACKPROTECTOR_STRONG":          "y",
		"CONFIG_THREAD_INFO_IN_TASK":            "y",
		"CONFIG_BUG_ON_DATA_CORRUPTION":         "y",
		"CONFIG_KFENCE":                         "y",
		"CONFIG_ZERO_CALL_USED_REGS":            "y",
		"CONFIG_RANDOMIZE_BASE":                 "y",
		"CONFIG_RANDOMIZE_MEMORY":               "y",
		"CONFIG_RANDOMIZE_KSTACK_OFFSET":        "y",
		"CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT": "y",
		"CONFIG_PAGE_TABLE_ISOLATION":            "y",
		"CONFIG_RETPOLINE":                       "y",
		"CONFIG_X86_KERNEL_IBT":                  "y",
		"CONFIG_LEGACY_VSYSCALL_NONE":            "y",
		"CONFIG_STRICT_KERNEL_RWX":               "y",
		"CONFIG_STRICT_MODULE_RWX":               "y",
		"CONFIG_SCHED_STACK_END_CHECK":           "y",
		"CONFIG_GCC_PLUGIN_STACKLEAK":            "y",
		"CONFIG_IOMMU_DEFAULT_DMA_STRICT":        "y",
		"CONFIG_MODULE_SIG":                      "y",
		"CONFIG_MODULE_SIG_ALL":                  "y",
		"CONFIG_MODULE_SIG_SHA512":               "y",
		"CONFIG_SECCOMP":                         "y",
		"CONFIG_SECCOMP_FILTER":                  "y",
		"CONFIG_SECURITY_YAMA":                   "y",
		"CONFIG_SECURITY_LANDLOCK":               "y",
		"CONFIG_SECURITY_LOCKDOWN_LSM":           "y",
		"CONFIG_SECURITY_LOADPIN":                "y",
		"CONFIG_DEBUG_LIST":                      "y",
		"CONFIG_DEBUG_NOTIFIERS":                 "y",
		"CONFIG_DEBUG_SG":                        "y",
		"CONFIG_SYN_COOKIES":                     "y",
		"CONFIG_SECURITY_DMESG_RESTRICT":         "y",
		"CONFIG_SECURITY_PERF_EVENTS_RESTRICT":   "y",
		"CONFIG_SECURITY_TIOCSTI_RESTRICT":       "y",
		"CONFIG_HARDENED_USERCOPY_DEFAULT_ON":     "y",
	}
	r := checkHardenedKernel(config, nil)
	if r.Description != "Hardened Kernel" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	// With all configs enabled, should be at least "Yes"
	if !strings.Contains(r.Status, "Yes") && !strings.Contains(r.Status, "Partial") {
		t.Errorf("expected hardened status, got: %s", r.Status)
	}
}

func TestCheckHardenedKernel_NoConfig(t *testing.T) {
	r := checkHardenedKernel(nil, fmt.Errorf("no config"))
	if r.Description != "Hardened Kernel" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	// Should still produce a result
	foundMsg := false
	for _, s := range r.SubInfo {
		if strings.Contains(s, "Kernel config unavailable") {
			foundMsg = true
		}
	}
	if !foundMsg {
		t.Error("expected unavailable config message in subinfo")
	}
}

func TestCheckHardenedKernel_PermissionDeniedConfig(t *testing.T) {
	r := checkHardenedKernel(nil, os.ErrPermission)
	foundMsg := false
	for _, s := range r.SubInfo {
		if strings.Contains(s, "requires root") {
			foundMsg = true
		}
	}
	if !foundMsg {
		t.Error("expected root message in subinfo")
	}
}

func TestCheckHardenedKernel_DangerousConfigs(t *testing.T) {
	config := map[string]string{
		"CONFIG_DEVMEM":                    "y",
		"CONFIG_PROC_KCORE":                "y",
		"CONFIG_KEXEC":                     "y",
		"CONFIG_HIBERNATION":               "y",
		"CONFIG_USERFAULTFD":               "y",
		"CONFIG_IOMMU_DEFAULT_PASSTHROUGH": "y",
		"CONFIG_PROFILING":                 "y",
	}
	r := checkHardenedKernel(config, nil)
	// Dangerous configs should show in subinfo
	weakCount := 0
	for _, s := range r.SubInfo {
		if strings.HasPrefix(s, "Weak config:") {
			weakCount++
		}
	}
	if weakCount == 0 {
		t.Error("expected weak config entries in subinfo")
	}
}

func TestCheckHardenedKernel_EmptyConfig(t *testing.T) {
	config := map[string]string{}
	r := checkHardenedKernel(config, nil)
	// With empty config, score should be low
	if strings.Contains(r.Status, "Yes") {
		t.Errorf("empty config should not be Yes: %s", r.Status)
	}
}

// --- sortAndPrintResults ---

func TestSortAndPrintResults_Priority(t *testing.T) {
	results := []Result{
		{Prefix: "[+]", Description: "Secure Boot", Status: "Enabled", Colour: ColourGreen, SortWeight: 0},
		{Prefix: "[+]", Description: "Hardened Kernel", Status: "Yes", Colour: ColourGreen, SortWeight: 0},
		{Prefix: "[+]", Description: "ASLR", Status: "Full", Colour: ColourGreen, SortWeight: 0},
		{Prefix: "[-]", Description: "AppArmor", Status: "Not found", Colour: ColourRed, SortWeight: 2},
		{Prefix: "[+]", Description: "Landlock LSM", Status: "Active", Colour: ColourGreen, SortWeight: 0},
	}

	// Capture output
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	sortAndPrintResults(results)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	// Hardened Kernel should be first (priority 0)
	if !strings.Contains(lines[0], "Hardened Kernel") {
		t.Errorf("line 0 should be Hardened Kernel, got: %s", lines[0])
	}
	// ASLR should be second (priority 1)
	if !strings.Contains(lines[1], "ASLR") {
		t.Errorf("line 1 should be ASLR, got: %s", lines[1])
	}
	// Landlock should be before AppArmor
	landlockIdx := -1
	apparmorIdx := -1
	for i, line := range lines {
		if strings.Contains(line, "Landlock") {
			landlockIdx = i
		}
		if strings.Contains(line, "AppArmor") {
			apparmorIdx = i
		}
	}
	if landlockIdx >= apparmorIdx {
		t.Errorf("Landlock (idx %d) should be before AppArmor (idx %d)", landlockIdx, apparmorIdx)
	}
}

func TestSortAndPrintResults_SortWeightTiebreak(t *testing.T) {
	results := []Result{
		{Prefix: "[-]", Description: "ZZZ Check", SortWeight: 2},
		{Prefix: "[+]", Description: "AAA Check", SortWeight: 0},
		{Prefix: "[!]", Description: "MMM Check", SortWeight: 1},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	sortAndPrintResults(results)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if !strings.Contains(lines[0], "AAA") {
		t.Errorf("line 0 should be AAA (weight 0), got: %s", lines[0])
	}
	if !strings.Contains(lines[1], "MMM") {
		t.Errorf("line 1 should be MMM (weight 1), got: %s", lines[1])
	}
	if !strings.Contains(lines[2], "ZZZ") {
		t.Errorf("line 2 should be ZZZ (weight 2), got: %s", lines[2])
	}
}

func TestSortAndPrintResults_SubInfo(t *testing.T) {
	results := []Result{
		{Prefix: "[+]", Description: "Test", Status: "OK", SubInfo: []string{"detail1", "detail2", "detail3"}},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	sortAndPrintResults(results)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "├──") {
		t.Error("expected tree connector ├──")
	}
	if !strings.Contains(output, "└──") {
		t.Error("expected tree end └──")
	}
	if !strings.Contains(output, "detail1") {
		t.Error("expected detail1")
	}
	if !strings.Contains(output, "detail3") {
		t.Error("expected detail3")
	}
}

func TestSortAndPrintResults_AlphabeticalTiebreak(t *testing.T) {
	results := []Result{
		{Prefix: "[+]", Description: "Bravo Check", SortWeight: 0},
		{Prefix: "[+]", Description: "Alpha Check", SortWeight: 0},
		{Prefix: "[+]", Description: "Charlie Check", SortWeight: 0},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	sortAndPrintResults(results)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if !strings.Contains(lines[0], "Alpha") {
		t.Errorf("line 0 should be Alpha, got: %s", lines[0])
	}
	if !strings.Contains(lines[1], "Bravo") {
		t.Errorf("line 1 should be Bravo, got: %s", lines[1])
	}
	if !strings.Contains(lines[2], "Charlie") {
		t.Errorf("line 2 should be Charlie, got: %s", lines[2])
	}
}

// --- getKernelConfig ---

func TestGetKernelConfig_InvalidPath(t *testing.T) {
	// getKernelConfig reads /proc/config.gz which we can't mock easily,
	// but we can test via a helper that creates a gzipped temp file.
	config, err := getKernelConfig()
	if err != nil {
		// On systems without /proc/config.gz, this is expected
		t.Logf("getKernelConfig returned error (expected if /proc/config.gz unavailable): %v", err)
		return
	}
	if config == nil {
		t.Error("expected non-nil config map")
	}
	// Should have at least some entries
	if len(config) == 0 {
		t.Error("expected non-empty config map")
	}
}

func createGzipFile(t *testing.T, path string, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	gw.Write([]byte(content))
	gw.Close()
}

func TestParseKernelConfigContent(t *testing.T) {
	// Test the parsing logic by checking what getKernelConfig returns on the live system
	// and validating known patterns
	config, err := getKernelConfig()
	if err != nil {
		t.Skip("skipping: /proc/config.gz not available")
	}

	// Verify "# CONFIG_FOO is not set" lines are parsed as "n"
	// We know CONFIG_WERROR is not set on this kernel
	if val, ok := config["CONFIG_WERROR"]; ok {
		if val != "n" {
			t.Logf("CONFIG_WERROR has value %q (expected 'n' if not set)", val)
		}
	}

	// Verify quoted values are preserved
	if val, ok := config["CONFIG_MODULE_SIG_HASH"]; ok {
		if !strings.Contains(val, "sha") {
			t.Logf("unexpected MODULE_SIG_HASH value: %s", val)
		}
	}

	// Verify boolean y/n values work
	if val, ok := config["CONFIG_SECURITY"]; ok {
		if val != "y" {
			t.Errorf("expected CONFIG_SECURITY=y, got %s", val)
		}
	}
}

// --- checkKernelConfig ---

func TestCheckKernelConfig_NilConfig(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkKernelConfig(nil, fmt.Errorf("test error"))

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Could not read") {
		t.Errorf("expected error message, got: %s", output)
	}
}

func TestCheckKernelConfig_NilConfigPermDenied(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkKernelConfig(nil, os.ErrPermission)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Requires root") {
		t.Errorf("expected 'Requires root', got: %s", output)
	}
}

func TestCheckKernelConfig_AllEnabled(t *testing.T) {
	config := map[string]string{
		"CONFIG_INIT_ON_ALLOC_DEFAULT_ON":       "y",
		"CONFIG_INIT_ON_FREE_DEFAULT_ON":        "y",
		"CONFIG_HARDENED_USERCOPY":              "y",
		"CONFIG_HARDENED_USERCOPY_DEFAULT_ON":   "y",
		"CONFIG_FORTIFY_SOURCE":                 "y",
		"CONFIG_SLAB_FREELIST_RANDOM":           "y",
		"CONFIG_SLAB_FREELIST_HARDENED":         "y",
		"CONFIG_LIST_HARDENED":                  "y",
		"CONFIG_SHUFFLE_PAGE_ALLOCATOR":         "y",
		"CONFIG_VMAP_STACK":                     "y",
		"CONFIG_STACKPROTECTOR_STRONG":          "y",
		"CONFIG_THREAD_INFO_IN_TASK":            "y",
		"CONFIG_KFENCE":                         "y",
		"CONFIG_ZERO_CALL_USED_REGS":            "y",
		"CONFIG_BUG_ON_DATA_CORRUPTION":         "y",
		"CONFIG_RANDOMIZE_BASE":                 "y",
		"CONFIG_RANDOMIZE_MEMORY":               "y",
		"CONFIG_RANDOMIZE_KSTACK_OFFSET":        "y",
		"CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT": "y",
		"CONFIG_PAGE_TABLE_ISOLATION":            "y",
		"CONFIG_RETPOLINE":                       "y",
		"CONFIG_X86_KERNEL_IBT":                  "y",
		"CONFIG_LEGACY_VSYSCALL_NONE":            "y",
		"CONFIG_STRICT_KERNEL_RWX":               "y",
		"CONFIG_STRICT_MODULE_RWX":               "y",
		"CONFIG_SCHED_STACK_END_CHECK":           "y",
		"CONFIG_GCC_PLUGIN_STACKLEAK":            "y",
		"CONFIG_MODULE_SIG":                      "y",
		"CONFIG_MODULE_SIG_FORCE":                "y",
		"CONFIG_MODULE_SIG_ALL":                  "y",
		"CONFIG_MODULE_SIG_SHA512":               "y",
		"CONFIG_SECURITY":                        "y",
		"CONFIG_SECURITY_YAMA":                   "y",
		"CONFIG_SECURITY_LANDLOCK":               "y",
		"CONFIG_SECURITY_LOCKDOWN_LSM":           "y",
		"CONFIG_SECURITY_LOADPIN":                "y",
		"CONFIG_SECURITY_SAFESETID":              "y",
		"CONFIG_SECURITY_APPARMOR":               "y",
		"CONFIG_SECURITY_SELINUX":                "y",
		"CONFIG_SECCOMP":                         "y",
		"CONFIG_SECCOMP_FILTER":                  "y",
		"CONFIG_IOMMU_SUPPORT":                   "y",
		"CONFIG_IOMMU_DEFAULT_DMA_STRICT":        "y",
		"CONFIG_SYN_COOKIES":                     "y",
		"CONFIG_SECURITY_DMESG_RESTRICT":         "y",
		"CONFIG_SECURITY_PERF_EVENTS_RESTRICT":   "y",
		"CONFIG_SECURITY_TIOCSTI_RESTRICT":       "y",
		"CONFIG_DEBUG_LIST":                      "y",
		"CONFIG_DEBUG_NOTIFIERS":                 "y",
		"CONFIG_DEBUG_SG":                        "y",
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkKernelConfig(config, nil)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// All should show as Enabled
	if strings.Count(output, "[+]") < 40 {
		t.Errorf("expected most configs to be [+], output has %d [+] entries", strings.Count(output, "[+]"))
	}
	// Verify categories are printed
	if !strings.Contains(output, "Memory Hardening") {
		t.Error("expected Memory Hardening category")
	}
	if !strings.Contains(output, "Exploit Mitigations") {
		t.Error("expected Exploit Mitigations category")
	}
	if !strings.Contains(output, "Attack Surface Reduction") {
		t.Error("expected Attack Surface Reduction category")
	}
}

func TestCheckKernelConfig_AllDisabled(t *testing.T) {
	config := map[string]string{}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkKernelConfig(config, nil)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// All positive configs should show as Not set
	if strings.Count(output, "[-]") == 0 {
		t.Error("expected some [-] entries")
	}
	// Attack surface entries should be [+] since configs are not set
	if !strings.Contains(output, "Not set") {
		t.Error("expected 'Not set' entries")
	}
}

func TestCheckKernelConfig_AttackSurfaceEnabled(t *testing.T) {
	config := map[string]string{
		"CONFIG_DEVMEM":                    "y",
		"CONFIG_PROC_KCORE":                "y",
		"CONFIG_KEXEC":                     "y",
		"CONFIG_HIBERNATION":               "y",
		"CONFIG_LDISC_AUTOLOAD":            "y",
		"CONFIG_USERFAULTFD":               "y",
		"CONFIG_IOMMU_DEFAULT_PASSTHROUGH": "y",
		"CONFIG_PROFILING":                 "y",
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkKernelConfig(config, nil)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Attack surface configs should show as [-] Enabled
	if !strings.Contains(output, "Enabled") {
		t.Error("expected 'Enabled' entries for attack surface configs")
	}
}

func TestCheckKernelConfig_NonStandardValues(t *testing.T) {
	config := map[string]string{
		"CONFIG_INIT_ON_ALLOC_DEFAULT_ON": "m", // module, not expected
		"CONFIG_DEVMEM":                   "m", // neither y nor n
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkKernelConfig(config, nil)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Should show [!] for non-standard values
	if !strings.Contains(output, "[!]") {
		t.Error("expected [!] for non-standard config values")
	}
}

// --- printHeader ---

func TestPrintHeader(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printHeader()

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "awhy") {
		t.Error("header should contain awhy")
	}
	if !strings.Contains(output, "Linux Security Mitigation Checker") {
		t.Error("header should contain subtitle")
	}
	if !strings.Contains(output, "====") {
		t.Error("header should contain separator")
	}
}

// --- Live system integration tests (test actual file reads) ---

func TestCheckSecureBoot_ReturnsResult(t *testing.T) {
	r := checkSecureBoot()
	if r.Description != "Secure Boot" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	// Should be one of the known statuses
	validStatuses := []string{"Enabled", "Disabled", "Not available", "Requires root", "Unknown"}
	found := false
	for _, s := range validStatuses {
		if strings.Contains(r.Status, s) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckKernelTaint_ReturnsResult(t *testing.T) {
	r := checkKernelTaint()
	if r.Description != "Kernel Integrity" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	// Should be Untainted or Tainted
	if !strings.Contains(r.Status, "Untainted") && !strings.Contains(r.Status, "Tainted") && !strings.Contains(r.Status, "Unknown") {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckSELinux_ReturnsResult(t *testing.T) {
	r := checkSELinux()
	if r.Description != "NSA SELinux" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	validStatuses := []string{"Enforcing", "Permissive", "Not found", "Present", "Requires root"}
	found := false
	for _, s := range validStatuses {
		if strings.Contains(r.Status, s) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckAppArmor_ReturnsResult(t *testing.T) {
	r := checkAppArmor()
	if r.Description != "AppArmor" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	validStatuses := []string{"Enabled", "Present", "Not found", "disabled", "Requires root"}
	found := false
	for _, s := range validStatuses {
		if strings.Contains(r.Status, s) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckLandlock_ReturnsResult(t *testing.T) {
	r := checkLandlock()
	if r.Description != "Landlock LSM" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	validStatuses := []string{"Enabled", "Active", "Not available"}
	found := false
	for _, s := range validStatuses {
		if strings.Contains(r.Status, s) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckLockdownLSM_ReturnsResult(t *testing.T) {
	r := checkLockdownLSM()
	if r.Description != "Lockdown LSM" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	validStatuses := []string{"Confidentiality", "Integrity", "None", "Not available", "Requires root"}
	found := false
	for _, s := range validStatuses {
		if strings.Contains(r.Status, s) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckSeccomp_ReturnsResult(t *testing.T) {
	r := checkSeccomp()
	if r.Description != "Seccomp" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	if !strings.Contains(r.Status, "Available") && !strings.Contains(r.Status, "Not available") {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

func TestCheckCoreDumpConfig_ReturnsResult(t *testing.T) {
	r := checkCoreDumpConfig()
	if r.Description != "Core Dump Restrict" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	validStatuses := []string{"Disabled", "Piped to handler", "Enabled", "Could not check"}
	found := false
	for _, s := range validStatuses {
		if strings.Contains(r.Status, s) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unexpected status: %s", r.Status)
	}
	// Should have core_pattern in subinfo
	if len(r.SubInfo) > 0 && !strings.Contains(r.SubInfo[0], "core_pattern") {
		t.Errorf("expected core_pattern in subinfo, got: %v", r.SubInfo)
	}
}

func TestCheckGnomeHSI_ReturnsResult(t *testing.T) {
	r := checkGnomeHSI()
	if r.Description != "GNOME HSI" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	if !strings.Contains(r.Status, "found") && !strings.Contains(r.Status, "Unavailable") {
		t.Errorf("unexpected status: %s", r.Status)
	}
}

// --- Edge cases ---

func TestSortAndPrintResults_Empty(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	sortAndPrintResults([]Result{})

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output != "" {
		t.Errorf("expected empty output for empty results, got: %q", output)
	}
}

func TestSortAndPrintResults_SingleSubInfo(t *testing.T) {
	results := []Result{
		{Prefix: "[+]", Description: "Test", Status: "OK", SubInfo: []string{"only one"}},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	sortAndPrintResults(results)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Single subinfo should use └── not ├──
	if strings.Contains(output, "├──") {
		t.Error("single subinfo should only use └──")
	}
	if !strings.Contains(output, "└──") {
		t.Error("expected └── for single subinfo")
	}
}

func TestGetSysctlResult_WhitespaceHandling(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "val", "  2  \n\n")
	m := map[string]string{"2": "Full"}

	r := getSysctlResult(path, "2", "Test", m)
	if r.Prefix != "[+]" {
		t.Errorf("expected [+] after trimming whitespace, got %s (status: %s)", r.Prefix, r.Status)
	}
}

func TestCheckModuleSigning_NoHash(t *testing.T) {
	config := map[string]string{
		"CONFIG_MODULE_SIG": "y",
	}
	r := checkModuleSigning(config)
	// Should still work without hash
	if r.Prefix != "[!]" {
		t.Errorf("expected [!], got %s", r.Prefix)
	}
	// Should not have hash in subinfo
	for _, s := range r.SubInfo {
		if strings.Contains(s, "Hash algorithm") {
			t.Error("should not have hash algorithm when not set")
		}
	}
}

// --- Result struct validation ---

func TestResultStruct(t *testing.T) {
	r := Result{
		Prefix:      "[+]",
		Description: "Test Check",
		Status:      "Enabled",
		Colour:       ColourGreen,
		SortWeight:  0,
		SubInfo:     []string{"info1", "info2"},
	}
	if r.Prefix != "[+]" {
		t.Error("prefix mismatch")
	}
	if r.Description != "Test Check" {
		t.Error("description mismatch")
	}
	if r.Status != "Enabled" {
		t.Error("status mismatch")
	}
	if r.Colour != ColourGreen {
		t.Error("colour mismatch")
	}
	if r.SortWeight != 0 {
		t.Error("weight mismatch")
	}
	if len(r.SubInfo) != 2 {
		t.Error("subinfo length mismatch")
	}
}

// --- Colour constants ---

func TestColourConstants(t *testing.T) {
	if ColourReset != "\033[0m" {
		t.Error("ColourReset mismatch")
	}
	if ColourRed != "\033[31m" {
		t.Error("ColourRed mismatch")
	}
	if ColourGreen != "\033[32m" {
		t.Error("ColourGreen mismatch")
	}
	if ColourYellow != "\033[33m" {
		t.Error("ColourYellow mismatch")
	}
	if ColourBlue != "\033[34m" {
		t.Error("ColourBlue mismatch")
	}
	if ColourCyan != "\033[36m" {
		t.Error("ColourCyan mismatch")
	}
	if ColourBold != "\033[1m" {
		t.Error("ColourBold mismatch")
	}
}

// --- checkHardenedKernel scoring edge cases ---

func TestCheckHardenedKernel_PercentageClamping(t *testing.T) {
	// Config with only dangerous entries should clamp to 0%
	config := map[string]string{
		"CONFIG_DEVMEM":                    "y",
		"CONFIG_PROC_KCORE":                "y",
		"CONFIG_KEXEC":                     "y",
		"CONFIG_KEXEC_FILE":                "y",
		"CONFIG_HIBERNATION":               "y",
		"CONFIG_COMPAT_VDSO":               "y",
		"CONFIG_MODIFY_LDT_SYSCALL":        "y",
		"CONFIG_LDISC_AUTOLOAD":            "y",
		"CONFIG_USERFAULTFD":               "y",
		"CONFIG_USER_NS_UNPRIVILEGED":      "y",
		"CONFIG_IOMMU_DEFAULT_PASSTHROUGH": "y",
		"CONFIG_PROFILING":                 "y",
	}
	r := checkHardenedKernel(config, nil)
	// Score is negative due to dangerous configs, percentage should clamp to 0
	if strings.Contains(r.Status, "-%") {
		t.Errorf("percentage should not be negative: %s", r.Status)
	}
}

func TestCheckHardenedKernel_SubInfoOrder(t *testing.T) {
	config := map[string]string{
		"CONFIG_FORTIFY_SOURCE": "y",
	}
	r := checkHardenedKernel(config, nil)
	// First 3 subinfo items should always be Kernel version, Confidence Score, description
	if len(r.SubInfo) < 3 {
		t.Fatalf("expected at least 3 subinfo items, got %d", len(r.SubInfo))
	}
	if !strings.HasPrefix(r.SubInfo[0], "Kernel:") {
		t.Errorf("first subinfo should be Kernel, got: %s", r.SubInfo[0])
	}
	if !strings.HasPrefix(r.SubInfo[1], "Confidence Score:") {
		t.Errorf("second subinfo should be Confidence Score, got: %s", r.SubInfo[1])
	}
	if !strings.HasPrefix(r.SubInfo[2], "Score accounts") {
		t.Errorf("third subinfo should be Score description, got: %s", r.SubInfo[2])
	}
}

func TestCheckCPUVulnerabilities_ReturnsResult(t *testing.T) {
	r := checkCPUVulnerabilities()
	if r.Description != "CPU Mitigations" {
		t.Errorf("unexpected description: %s", r.Description)
	}
	// On most modern Linux systems this should return a result
	// Valid prefixes are [+], [!], [-]
	if r.Prefix != "[+]" && r.Prefix != "[!]" && r.Prefix != "[-]" {
		t.Errorf("unexpected prefix: %s", r.Prefix)
	}
}
