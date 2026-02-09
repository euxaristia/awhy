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
	generalResults = append(generalResults, getFileValueResult("/proc/sys/kernel/randomize_va_space", "2", "ASLR"))
	generalResults = append(generalResults, getFileValueResult("/proc/sys/kernel/kptr_restrict", "2", "Kernel Pointer Restrict"))
	generalResults = append(generalResults, getFileValueResult("/proc/sys/kernel/dmesg_restrict", "1", "dmesg Restrict"))
	generalResults = append(generalResults, getFileValueResult("/proc/sys/net/core/bpf_jit_harden", "2", "BPF JIT Hardening"))
	generalResults = append(generalResults, checkSELinux())
	generalResults = append(generalResults, checkAppArmor())
	generalResults = append(generalResults, getFileValueResult("/proc/sys/kernel/yama/ptrace_scope", "1", "Yama ptrace_scope"))
	generalResults = append(generalResults, getFileValueResult("/proc/sys/fs/protected_hardlinks", "1", "Protected Hardlinks"))
	generalResults = append(generalResults, getFileValueResult("/proc/sys/fs/protected_symlinks", "1", "Protected Symlinks"))
	generalResults = append(generalResults, getFileValueResult("/proc/sys/fs/protected_fifos", "1", "Protected FIFOs"))
	generalResults = append(generalResults, getFileValueResult("/proc/sys/fs/protected_regular", "1", "Protected Regular Files"))

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

func checkHardenedKernel() Result {
	var subInfo []string
	score := 0 // Higher is better

	// Check 1: Kernel Name
	out, err := exec.Command("uname", "-r").Output()
	version := ""
	if err == nil {
		version = strings.TrimSpace(string(out))
		lowerVersion := strings.ToLower(version)
		if strings.Contains(lowerVersion, "hardened") {
			subInfo = append(subInfo, fmt.Sprintf("Kernel version string contains 'hardened': %s", version))
			score += 2
		} else if strings.Contains(lowerVersion, "lts") {
			subInfo = append(subInfo, fmt.Sprintf("Kernel version indicates LTS: %s", version))
		}
	}

	// Check 2: Kernel Command Line Arguments
	cmdlineBytes, err := ioutil.ReadFile("/proc/cmdline")
	if err == nil {
		cmdline := string(cmdlineBytes)
		args := strings.Fields(cmdline)
		
		importantArgs := map[string]string{
			"slab_nomerge":            "Disables merging of slab caches",
			"slub_debug=FZP":          "Enables sanity checks for SLUB",
			"init_on_alloc=1":         "Zeroes memory on allocation",
			"init_on_free=1":          "Zeroes memory on free",
			"page_alloc.shuffle=1":    "Randomizes page allocator",
			"pti=on":                  "Enables Kernel Page Table Isolation",
			"randomize_kstack_offset=on": "Randomizes kernel stack offset",
			"vsyscall=none":           "Disables legacy vsyscalls",
			"debugfs=off":             "Disables debugfs",
			"oops=panic":              "Panics on oops",
			"lockdown=confidentiality": "Enables lockdown mode (confidentiality)",
			"lockdown=integrity":       "Enables lockdown mode (integrity)",
		}

		for _, arg := range args {
			for key, desc := range importantArgs {
				if arg == key || (strings.Contains(key, "=") && arg == key) || (!strings.Contains(key, "=") && strings.Contains(arg, key)) {
					// Simple matching for now, can be improved
					if arg == key {
						subInfo = append(subInfo, fmt.Sprintf("Boot parameter found: %s (%s)", arg, desc))
						score += 1
					}
				}
			}
		}
	}

	// Check 3: Lockdown Mode (Direct check)
	lockdownBytes, err := ioutil.ReadFile("/sys/kernel/security/lockdown")
	if err == nil {
		lockdownContent := string(lockdownBytes)
		// Format is usually [none] integrity confidentiality or similar, with [] around active
		if strings.Contains(lockdownContent, "[integrity]") {
			subInfo = append(subInfo, "Lockdown mode enabled: integrity")
			score += 2
		} else if strings.Contains(lockdownContent, "[confidentiality]") {
			subInfo = append(subInfo, "Lockdown mode enabled: confidentiality")
			score += 3
		}
	}

	// Check 4: Specific Hardening Sysctls (PaX/Grsecurity legacy or modern equivalents)
	// Just checking existence for now as a strong signal
	if _, err := os.Stat("/proc/sys/kernel/pax"); err == nil {
		subInfo = append(subInfo, "PaX sysctl directory detected")
		score += 5
	}
	if _, err := os.Stat("/proc/sys/kernel/grsecurity"); err == nil {
		subInfo = append(subInfo, "Grsecurity sysctl directory detected")
		score += 5
	}

	// Determine Result
	status := "No (Standard kernel)"
	color := ColorRed
	weight := 2

	if score >= 2 {
		status = fmt.Sprintf("Yes (Score: %d)", score)
		color = ColorGreen
		weight = 0
	} else if score > 0 {
		status = fmt.Sprintf("Partial (Score: %d)", score)
		color = ColorYellow
		weight = 1
	}

	// If score is low but we detected standard kernel, might just be standard.
	// But if we found *some* evidence, list it.

	if len(subInfo) == 0 {
		return Result{"[-]", "Hardened Kernel", status, color, weight, nil}
	}

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