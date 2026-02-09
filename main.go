package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

type Result struct {
	Prefix      string
	Description string
	Status      string
	Color       string
	SortWeight  int      // 0 for [+], 1 for [!], 2 for [-]
	SubInfo     []string // Additional details to display
}

func main() {
	printHeader()

	if runtime.GOOS != "linux" {
		fmt.Printf("%sError: This tool is designed for Linux systems only.%s\n", ColorRed, ColorReset)
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Printf("%s[!] Warning: Not running as root. Some checks may fail or be inaccurate.%s\n", ColorYellow, ColorReset)
		fmt.Println()
	}

	var generalResults []Result
	generalResults = append(generalResults, checkHardenedKernel())
	generalResults = append(generalResults, checkSecureBoot())
	generalResults = append(generalResults, checkKernelTaint())
	generalResults = append(generalResults, checkGnomeHSI())

	aslrMap := map[string]string{"0": "Disabled", "1": "Conservative", "2": "Full"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/randomize_va_space", "2", "ASLR", aslrMap))

	kptrMap := map[string]string{"0": "Disabled", "1": "Hides for non-privileged", "2": "Hides for all"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/kptr_restrict", "2", "Kernel Pointer Restrict", kptrMap))

	dmesgMap := map[string]string{"0": "Disabled", "1": "Restricted"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/dmesg_restrict", "1", "dmesg Restrict", dmesgMap))

	bpfMap := map[string]string{"0": "Disabled", "1": "Enabled (Unprivileged)", "2": "Enabled (All)"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/net/core/bpf_jit_harden", "2", "BPF JIT Hardening", bpfMap))

	generalResults = append(generalResults, checkSELinux())
	generalResults = append(generalResults, checkAppArmor())

	ptraceMap := map[string]string{"0": "Classic", "1": "Restricted (Child)", "2": "Admin Only", "3": "None"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/yama/ptrace_scope", "1", "Yama ptrace_scope", ptraceMap))

	boolMap := map[string]string{"0": "Disabled", "1": "Enabled"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_hardlinks", "1", "Protected Hardlinks", boolMap))
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_symlinks", "1", "Protected Symlinks", boolMap))
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_fifos", "1", "Protected FIFOs", boolMap))
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_regular", "1", "Protected Regular Files", boolMap))

	sortAndPrintResults(generalResults)

	checkKernelConfig()
}

func printHeader() {
	header := `
    _              __        __      _   _               _ __   __     _   
   / \   _ __ ___  \ \      / /___  | | | | __ _ _ __ __| |\ \ / /__ _| |_ 
  / _ \ | '__/ _ \  \ \ /\ / / _ \  | |_| |/ _` + "`" + ` | '__/ _` + "`" + ` | \ V / -_)  _|
 / ___ \| | |  __/   \ V  V /  __/  |  _  | (_| | | | (_| |  | | |  __/ |_ 
/_/   \_\_|  \___|    \_/\_/ \___|  |_| |_|\__,_|_|  \__,_|  |_| \___|\__|
`
	fmt.Printf("%s%s%s", ColorCyan, header, ColorReset)
	fmt.Printf("%sAreWeHardYet - Linux Security Mitigation Checker%s\n", ColorBold, ColorReset)
	fmt.Println("========================================================")
}

func sortAndPrintResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].SortWeight != results[j].SortWeight {
			return results[i].SortWeight < results[j].SortWeight
		}

		// Custom logic for BPF JIT Hardening to keep it at the boundary between groups
		if results[i].Description == "BPF JIT Hardening" {
			if results[i].SortWeight == 0 { // Enabled: move to bottom of its group
				return false
			}
			if results[i].SortWeight == 2 { // Disabled/Missing: move to top of its group
				return true
			}
		}
		if results[j].Description == "BPF JIT Hardening" {
			if results[j].SortWeight == 0 { // Enabled: j is bottom, so i < j is true
				return true
			}
			if results[j].SortWeight == 2 { // Disabled/Missing: j is top, so i < j is false
				return false
			}
		}

		return results[i].Description < results[j].Description
	})

	for _, r := range results {
		fmt.Printf("%s%s %-40s: %s%s\n", r.Color, r.Prefix, r.Description, r.Status, ColorReset)
		for i, info := range r.SubInfo {
			connector := "├──"
			if i == len(r.SubInfo)-1 {
				connector = "└──"
			}
			fmt.Printf("   %s %s\n", connector, info)
		}
	}
}

func getFileValueResult(path string, expected string, description string) Result {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return Result{"[-]", description, "Could not read " + path, ColorRed, 2, nil}
	}
	val := strings.TrimSpace(string(content))
	if val == expected {
		return Result{"[+]", description, "Enabled (" + val + ")", ColorGreen, 0, nil}
	} else {
		return Result{"[!]", description, "Disabled or weak (" + val + ")", ColorYellow, 1, nil}
	}
}

func getSysctlResult(path string, expected string, description string, mapping map[string]string) Result {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return Result{"[-]", description, "Could not read " + path, ColorRed, 2, nil}
	}
	val := strings.TrimSpace(string(content))
	statusText, ok := mapping[val]
	if !ok {
		statusText = "Unknown"
	}

	status := fmt.Sprintf("%s (%s)", statusText, val)
	if val == expected {
		return Result{"[+]", description, status, ColorGreen, 0, nil}
	} else {
		return Result{"[!]", description, status, ColorYellow, 1, nil}
	}
}

func checkHardenedKernel() Result {
	var subInfo []string
	score := 0 // Higher is better

	// Check 1: Kernel Command Line Arguments (The primary source of truth)
	cmdlineBytes, err := ioutil.ReadFile("/proc/cmdline")
	if err == nil {
		cmdline := string(cmdlineBytes)
		args := strings.Fields(cmdline)
		
		positiveArgs := map[string]string{
			"slab_nomerge":            "Disables merging of slab caches (+1)",
			"slub_debug=FZP":          "Enables sanity checks for SLUB (+1)",
			"init_on_alloc=1":         "Zeroes memory on allocation (+1)",
			"init_on_free=1":          "Zeroes memory on free (+1)",
			"page_alloc.shuffle=1":    "Randomizes page allocator (+1)",
			"pti=on":                  "Enables Kernel Page Table Isolation (+1)",
			"randomize_kstack_offset=on": "Randomizes kernel stack offset (+1)",
			"vsyscall=none":           "Disables legacy vsyscalls (+1)",
			"debugfs=off":             "Disables debugfs (+1)",
			"oops=panic":              "Panics on oops (+1)",
			"lockdown=confidentiality": "Enables lockdown mode: confidentiality (+3)",
			"lockdown=integrity":       "Enables lockdown mode: integrity (+2)",
			"page_poison=1":           "Enables page poisoning (+1)",
			"slub_debug=P":            "Enables SLUB poisoning (+1)",
			"spectre_v2=on":           "Enables Spectre v2 mitigation (+1)",
			"spec_store_bypass_disable=on": "Enables Speculative Store Bypass mitigation (+1)",
			"l1tf=full,force":         "Enables full L1TF mitigation (+1)",
			"mds=full,raw":            "Enables full MDS mitigation (+1)",
			"tsx=off":                 "Disables TSX (+1)",
			"iommu=force":             "Forces IOMMU usage (+1)",
		}

		negativeArgs := map[string]string{
			"vsyscall=emulate": "Uses legacy vsyscall emulation (-2)",
			"vsyscall=native":  "Uses legacy vsyscall native mode (-3)",
			"debugfs=on":       "Explicitly enables debugfs (-1)",
			"nokaslr":          "Explicitly disables KASLR (-5)",
			"nopti":            "Explicitly disables PTI (-3)",
			"nospectre_v2":     "Explicitly disables Spectre v2 mitigations (-3)",
			"mitigations=off":  "Explicitly disables all mitigations (-10)",
		}

		for _, arg := range args {
			// Check Positive
			if desc, ok := positiveArgs[arg]; ok {
				subInfo = append(subInfo, fmt.Sprintf("Hardening parameter: %s (%s)", arg, desc))
				if strings.Contains(desc, "+3") {
					score += 3
				} else if strings.Contains(desc, "+2") {
					score += 2
				} else {
					score += 1
				}
			}
			// Check Negative
			if desc, ok := negativeArgs[arg]; ok {
				subInfo = append(subInfo, fmt.Sprintf("Standard/Weak parameter: %s (%s)", arg, desc))
				if strings.Contains(desc, "-10") {
					score -= 10
				} else if strings.Contains(desc, "-5") {
					score -= 5
				} else if strings.Contains(desc, "-3") {
					score -= 3
				} else if strings.Contains(desc, "-2") {
					score -= 2
				} else {
					score -= 1
				}
			}
		}
	}

	// Check 2: Lockdown Mode (Direct check)
	lockdownBytes, err := ioutil.ReadFile("/sys/kernel/security/lockdown")
	if err == nil {
		lockdownContent := string(lockdownBytes)
		if strings.Contains(lockdownContent, "[integrity]") {
			subInfo = append(subInfo, "Lockdown mode enabled (+2 points): integrity")
			score += 2
		} else if strings.Contains(lockdownContent, "[confidentiality]") {
			subInfo = append(subInfo, "Lockdown mode enabled (+3 points): confidentiality")
			score += 3
		} else if strings.Contains(lockdownContent, "[none]") {
			subInfo = append(subInfo, "Lockdown mode explicitly disabled (-1 point)")
			score -= 1
		}
	}

	// Check 3: Specific Hardening Sysctls
	if _, err := os.Stat("/proc/sys/kernel/pax"); err == nil {
		subInfo = append(subInfo, "PaX sysctl directory detected (+5 points)")
		score += 5
	}
	if _, err := os.Stat("/proc/sys/kernel/grsecurity"); err == nil {
		subInfo = append(subInfo, "Grsecurity sysctl directory detected (+5 points)")
		score += 5
	}

	// Check 4: Version string as a MINOR hint only if score is already high, 
	// but we won't add points for it anymore. Instead, we just use it for the display.
	out, _ := exec.Command("uname", "-r").Output()
	version := strings.TrimSpace(string(out))

	// Determine Result
	status := "No (Standard kernel)"
	color := ColorRed
	weight := 2

	maxScore := 20 // Target score for 100% hardening
	percentage := (score * 100) / maxScore
	if percentage > 100 {
		percentage = 100
	}
	if percentage < 0 {
		percentage = 0
	}

	if score >= 3 {
		status = fmt.Sprintf("Yes (%d%% Hardened)", percentage)
		color = ColorGreen
		weight = 0
	} else if score > 0 {
		status = fmt.Sprintf("Partial (%d%% Hardened)", percentage)
		color = ColorYellow
		weight = 1
	} else if score < 0 {
		status = fmt.Sprintf("Weak/Insecure (%d%% Hardened)", percentage)
		color = ColorRed
		weight = 2
	}

	if len(subInfo) == 0 {
		return Result{"[-]", "Hardened Kernel", "No (0% Hardened)", ColorRed, 2, []string{"No hardening indicators found in boot parameters or sysctls."}}
	}

	subInfo = append([]string{
		fmt.Sprintf("Kernel: %s", version),
		fmt.Sprintf("Confidence Score: %d/%d points (%d%%)", score, maxScore, percentage),
		"Score is based on real-time boot parameters and kernel security features.",
	}, subInfo...)

	return Result{
		Prefix:      getPrefix(weight),
		Description: "Hardened Kernel",
		Status:      status,
		Color:       color,
		SortWeight:  weight,
		SubInfo:     subInfo,
	}
}

func getPrefix(weight int) string {
	switch weight {
	case 0:
		return "[+]"
	case 1:
		return "[!]"
	default:
		return "[-]"
	}
}

func checkSELinux() Result {
	_, err := os.Stat("/sys/fs/selinux")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/fs/selinux/enforce")
		if err == nil {
			if strings.TrimSpace(string(content)) == "1" {
				return Result{"[+]", "SELinux", "Enabled (Enforcing)", ColorGreen, 0, nil}
			} else {
				return Result{"[!]", "SELinux", "Enabled (Permissive)", ColorYellow, 1, nil}
			}
		}
		return Result{"[+]", "SELinux", "Present", ColorGreen, 0, nil}
	}
	return Result{"[-]", "SELinux", "Not found", ColorRed, 2, nil}
}

func checkAppArmor() Result {
	_, err := os.Stat("/sys/kernel/security/apparmor")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err == nil && strings.TrimSpace(string(content)) == "Y" {
			return Result{"[+]", "AppArmor", "Enabled", ColorGreen, 0, nil}
		} else {
			return Result{"[!]", "AppArmor", "Present but disabled", ColorYellow, 1, nil}
		}
	}
	return Result{"[-]", "AppArmor", "Not found", ColorRed, 2, nil}
}

func checkKernelConfig() {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
		fmt.Println("-------------------------------")
		fmt.Printf("%s[-] %-40s: %s%s\n", ColorRed, "Kernel Config Checks", "Could not open /proc/config.gz", ColorReset)
		return
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
		fmt.Println("-------------------------------")
		fmt.Printf("%s[-] %-40s: %s%s\n", ColorRed, "Kernel Config Checks", "Could not decompress /proc/config.gz", ColorReset)
		return
	}
	defer gz.Close()

	configs := map[string]string{
		"CONFIG_GCC_PLUGIN_STACKLEAK":       "y",
		"CONFIG_RANDOMIZE_KSTACK_OFFSET_ALL": "y",
		"CONFIG_INIT_ON_ALLOC_DEFAULT_ON":    "y",
		"CONFIG_INIT_ON_FREE_DEFAULT_ON":     "y",
		"CONFIG_HARDENED_USERCOPY":           "y",
		"CONFIG_FORTIFY_SOURCE":              "y",
		"CONFIG_SLAB_FREELIST_RANDOM":        "y",
		"CONFIG_SLAB_FREELIST_HARDENED":      "y",
	}

	found := make(map[string]string)
	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		line := scanner.Text()
		for cfg := range configs {
			if strings.HasPrefix(line, cfg+"=") {
				found[cfg] = strings.Split(line, "=")[1]
			}
		}
	}

	var results []Result
	for cfg, expected := range configs {
		val, ok := found[cfg]
		if ok && val == expected {
			results = append(results, Result{"[+]", cfg, "Enabled (" + val + ")", ColorGreen, 0, nil})
		} else if ok {
			results = append(results, Result{"[!]", cfg, "Disabled or different (" + val + ")", ColorYellow, 1, nil})
		} else {
			results = append(results, Result{"[-]", cfg, "Not set", ColorRed, 2, nil})
		}
	}

	fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
	fmt.Println("-------------------------------")
	sortAndPrintResults(results)
}

func checkSecureBoot() Result {
	path := "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if _, err := os.Stat("/sys/firmware/efi"); os.IsNotExist(err) {
			return Result{"[-]", "Secure Boot", "Not available (Legacy BIOS?)", ColorRed, 2, nil}
		}
		// Try to read /sys/kernel/security/securelevel or similar on some systems, but efivars is standard.
		return Result{"[?]", "Secure Boot", "Unknown (Could not read efivar)", ColorYellow, 1, nil}
	}
	// First 4 bytes are attributes, 5th byte is value.
	if len(data) >= 5 && data[4] == 1 {
		return Result{"[+]", "Secure Boot", "Enabled", ColorGreen, 0, nil}
	}
	return Result{"[-]", "Secure Boot", "Disabled", ColorRed, 2, nil}
}

func checkKernelTaint() Result {
	content, err := ioutil.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		return Result{"[?]", "Kernel Integrity", "Unknown (Could not read /proc/sys/kernel/tainted)", ColorRed, 2, nil}
	}

	var val int
	fmt.Sscanf(strings.TrimSpace(string(content)), "%d", &val)

	if val == 0 {
		return Result{"[+]", "Kernel Integrity", "Untainted", ColorGreen, 0, nil}
	}

	var subInfo []string
	taintBits := map[int]string{
		0:  "Proprietary module has been loaded (P)",
		1:  "Module has been forcibly loaded (F)",
		2:  "SMP with CPUs not designed for SMP (S)",
		3:  "Module was forcibly unloaded (R)",
		4:  "Machine Check Exception occurred (M)",
		5:  "Bad page referenced or some unexpected page flags (B)",
		6:  "Taint requested by userspace application (U)",
		7:  "Kernel died recently (OOPS or BUG) (D)",
		8:  "ACPI table overridden (A)",
		9:  "Kernel warning has occurred (W)",
		10: "Staging driver has been loaded (C)",
		11: "Workaround for bug in platform firmware applied (I)",
		12: "Externally-built ('out-of-tree') module has been loaded (O)",
		13: "Unsigned module has been loaded (E)",
		14: "Soft-lockup has occurred (L)",
		15: "Kernel has been live patched (K)",
		16: "Auxiliary taint, defined for and used by distros (X)",
		17: "Kernel was built with the struct randomization plugin (T)",
	}

	for bit, desc := range taintBits {
		if (val & (1 << bit)) != 0 {
			subInfo = append(subInfo, desc)
		}
	}

	// Check for common tainting modules
	modulesBytes, err := ioutil.ReadFile("/proc/modules")
	if err == nil {
		lines := strings.Split(string(modulesBytes), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				modName := fields[0]
				// Check for known proprietary/out-of-tree modules
				if modName == "nvidia" || modName == "nvidia_drm" || modName == "vboxdrv" || modName == "zfs" || modName == "wl" {
					subInfo = append(subInfo, fmt.Sprintf("Potential taint source detected: %s", modName))
				}
			}
		}
	}

	return Result{
		Prefix:      "[!]",
		Description: "Kernel Integrity",
		Status:      fmt.Sprintf("Tainted (Value: %d)", val),
		Color:       ColorYellow,
		SortWeight:  1,
		SubInfo:     subInfo,
	}
}

func checkGnomeHSI() Result {
	// 1. Try fwupdtool
	path, err := exec.LookPath("fwupdtool")
	if err == nil {
		// Just checking existence for now as running it might fail or require dbus
		return Result{"[?]", "GNOME HSI", "Tool found but not implemented", ColorYellow, 1, []string{"fwupdtool is present at " + path}}
	}

	// 2. Check for HSI attributes in /sys/class/dmi/id (rough proxy)
	// Real HSI requires complex calculation. Without fwupdtool, we can't reliably give a score.
	// But we can check if the service is running or check common paths.
	
	return Result{"[-]", "GNOME HSI", "Unavailable (fwupdtool not found)", ColorRed, 2, nil}
}