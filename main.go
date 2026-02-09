package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
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

	checkKernelName()
	checkASLR()
	checkKptrRestrict()
	checkDmesgRestrict()
	checkBpfJitHarden()
	checkSELinux()
	checkAppArmor()
	checkYama()
	checkFsProtections()
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

func printStatus(prefix string, description string, status string, color string) {
	fmt.Printf("%s%s %-30s: %s%s\n", color, prefix, description, status, ColorReset)
}

func checkFileValue(path string, expected string, description string) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		printStatus("[-]", description, "Could not read "+path, ColorRed)
		return
	}
	val := strings.TrimSpace(string(content))
	if val == expected {
		printStatus("[+]", description, "Enabled ("+val+")", ColorGreen)
	} else {
		printStatus("[!]", description, "Disabled or weak ("+val+")", ColorYellow)
	}
}

func checkKernelName() {
	out, err := exec.Command("uname", "-v").Output()
	if err == nil {
		version := strings.ToLower(string(out))
		if strings.Contains(version, "hardened") {
			printStatus("[+]", "Hardened Kernel", "Yes ("+strings.TrimSpace(string(out))+")", ColorGreen)
		} else {
			printStatus("[-]", "Hardened Kernel", "No (Standard kernel)", ColorRed)
		}
	}
}

func checkASLR() {
	checkFileValue("/proc/sys/kernel/randomize_va_space", "2", "ASLR")
}

func checkKptrRestrict() {
	checkFileValue("/proc/sys/kernel/kptr_restrict", "2", "Kernel Pointer Restrict")
}

func checkDmesgRestrict() {
	checkFileValue("/proc/sys/kernel/dmesg_restrict", "1", "dmesg Restrict")
}

func checkBpfJitHarden() {
	checkFileValue("/proc/sys/net/core/bpf_jit_harden", "2", "BPF JIT Hardening")
}

func checkSELinux() {
	_, err := os.Stat("/sys/fs/selinux")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/fs/selinux/enforce")
		if err == nil {
			if strings.TrimSpace(string(content)) == "1" {
				printStatus("[+]", "SELinux", "Enabled (Enforcing)", ColorGreen)
			} else {
				printStatus("[!]", "SELinux", "Enabled (Permissive)", ColorYellow)
			}
			return
		}
		printStatus("[+]", "SELinux", "Present", ColorGreen)
	} else {
		printStatus("[-]", "SELinux", "Not found", ColorRed)
	}
}

func checkAppArmor() {
	_, err := os.Stat("/sys/kernel/security/apparmor")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err == nil && strings.TrimSpace(string(content)) == "Y" {
			printStatus("[+]", "AppArmor", "Enabled", ColorGreen)
		} else {
			printStatus("[!]", "AppArmor", "Present but disabled", ColorYellow)
		}
	} else {
		printStatus("[-]", "AppArmor", "Not found", ColorRed)
	}
}

func checkYama() {
	checkFileValue("/proc/sys/kernel/yama/ptrace_scope", "1", "Yama ptrace_scope")
}

func checkFsProtections() {
	checkFileValue("/proc/sys/fs/protected_hardlinks", "1", "Protected Hardlinks")
	checkFileValue("/proc/sys/fs/protected_symlinks", "1", "Protected Symlinks")
	checkFileValue("/proc/sys/fs/protected_fifos", "1", "Protected FIFOs")
	checkFileValue("/proc/sys/fs/protected_regular", "1", "Protected Regular Files")
}

func checkKernelConfig() {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		printStatus("[-]", "Kernel Config Checks", "Could not open /proc/config.gz", ColorRed)
		return
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		printStatus("[-]", "Kernel Config Checks", "Could not decompress /proc/config.gz", ColorRed)
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

	fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
	fmt.Println("-------------------------------")
	for cfg, expected := range configs {
		val, ok := found[cfg]
		if ok && val == expected {
			printStatus("[+]", cfg, "Enabled ("+val+")", ColorGreen)
		} else if ok {
			printStatus("[!]", cfg, "Disabled or different ("+val+")", ColorYellow)
		} else {
			printStatus("[-]", cfg, "Not set", ColorRed)
		}
	}
}
