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
	SortWeight  int // 0 for [+], 1 for [!], 2 for [-]
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
	generalResults = append(generalResults, checkKernelName())
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
		return results[i].Description < results[j].Description
	})

	for _, r := range results {
		fmt.Printf("%s%s %-30s: %s%s\n", r.Color, r.Prefix, r.Description, r.Status, ColorReset)
	}
}

func getFileValueResult(path string, expected string, description string) Result {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return Result{"[-]", description, "Could not read " + path, ColorRed, 2}
	}
	val := strings.TrimSpace(string(content))
	if val == expected {
		return Result{"[+]", description, "Enabled (" + val + ")", ColorGreen, 0}
	} else {
		return Result{"[!]", description, "Disabled or weak (" + val + ")", ColorYellow, 1}
	}
}

func checkKernelName() Result {
	out, err := exec.Command("uname", "-r").Output()
	if err == nil {
		version := strings.ToLower(string(out))
		if strings.Contains(version, "hardened") {
			return Result{"[+]", "Hardened Kernel", "Yes (" + strings.TrimSpace(string(out)) + ")", ColorGreen, 0}
		} else {
			return Result{"[-]", "Hardened Kernel", "No (Standard kernel)", ColorRed, 2}
		}
	}
	return Result{"[-]", "Hardened Kernel", "Unknown", ColorRed, 2}
}

func checkSELinux() Result {
	_, err := os.Stat("/sys/fs/selinux")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/fs/selinux/enforce")
		if err == nil {
			if strings.TrimSpace(string(content)) == "1" {
				return Result{"[+]", "SELinux", "Enabled (Enforcing)", ColorGreen, 0}
			} else {
				return Result{"[!]", "SELinux", "Enabled (Permissive)", ColorYellow, 1}
			}
		}
		return Result{"[+]", "SELinux", "Present", ColorGreen, 0}
	}
	return Result{"[-]", "SELinux", "Not found", ColorRed, 2}
}

func checkAppArmor() Result {
	_, err := os.Stat("/sys/kernel/security/apparmor")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err == nil && strings.TrimSpace(string(content)) == "Y" {
			return Result{"[+]", "AppArmor", "Enabled", ColorGreen, 0}
		} else {
			return Result{"[!]", "AppArmor", "Present but disabled", ColorYellow, 1}
		}
	}
	return Result{"[-]", "AppArmor", "Not found", ColorRed, 2}
}

func checkKernelConfig() {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
		fmt.Println("-------------------------------")
		fmt.Printf("%s[-] %-30s: %s%s\n", ColorRed, "Kernel Config Checks", "Could not open /proc/config.gz", ColorReset)
		return
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
		fmt.Println("-------------------------------")
		fmt.Printf("%s[-] %-30s: %s%s\n", ColorRed, "Kernel Config Checks", "Could not decompress /proc/config.gz", ColorReset)
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
			results = append(results, Result{"[+]", cfg, "Enabled (" + val + ")", ColorGreen, 0})
		} else if ok {
			results = append(results, Result{"[!]", cfg, "Disabled or different (" + val + ")", ColorYellow, 1})
		} else {
			results = append(results, Result{"[-]", cfg, "Not set", ColorRed, 2})
		}
	}

	fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
	fmt.Println("-------------------------------")
	sortAndPrintResults(results)
}