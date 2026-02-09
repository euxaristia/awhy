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

func main() {
	fmt.Println("Are We Hardened Yet? - Linux Security Mitigation Checker")
	fmt.Println("========================================================")

	if runtime.GOOS != "linux" {
		fmt.Println("Error: This tool is designed for Linux systems only.")
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Println("[!] Warning: Not running as root. Some checks may fail or be inaccurate.")
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

func checkFileValue(path string, expected string, description string) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("[-] %-30s: Could not read %s\n", description, path)
		return
	}
	val := strings.TrimSpace(string(content))
	if val == expected {
		fmt.Printf("[+] %-30s: Enabled (%s)\n", description, val)
	} else {
		fmt.Printf("[!] %-30s: Disabled or weak (%s)\n", description, val)
	}
}

func checkKernelName() {
	out, err := exec.Command("uname", "-v").Output()
	if err == nil {
		version := strings.ToLower(string(out))
		if strings.Contains(version, "hardened") {
			fmt.Printf("[+] %-30s: Yes (%s)\n", "Hardened Kernel", strings.TrimSpace(string(out)))
		} else {
			fmt.Printf("[-] %-30s: No (Standard kernel)\n", "Hardened Kernel")
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
				fmt.Printf("[+] %-30s: Enabled (Enforcing)\n", "SELinux")
			} else {
				fmt.Printf("[!] %-30s: Enabled (Permissive)\n", "SELinux")
			}
			return
		}
		fmt.Printf("[+] %-30s: Present\n", "SELinux")
	} else {
		fmt.Printf("[-] %-30s: Not found\n", "SELinux")
	}
}

func checkAppArmor() {
	_, err := os.Stat("/sys/kernel/security/apparmor")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err == nil && strings.TrimSpace(string(content)) == "Y" {
			fmt.Printf("[+] %-30s: Enabled\n", "AppArmor")
		} else {
			fmt.Printf("[!] %-30s: Present but disabled\n", "AppArmor")
		}
	} else {
		fmt.Printf("[-] %-30s: Not found\n", "AppArmor")
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
		fmt.Printf("[-] %-30s: Could not open /proc/config.gz\n", "Kernel Config Checks")
		return
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		fmt.Printf("[-] %-30s: Could not decompress /proc/config.gz\n", "Kernel Config Checks")
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

	fmt.Println("\nKernel Configuration Hardening:")
	fmt.Println("-------------------------------")
	for cfg, expected := range configs {
		val, ok := found[cfg]
		if ok && val == expected {
			fmt.Printf("[+] %-30s: Enabled (%s)\n", cfg, val)
		} else if ok {
			fmt.Printf("[!] %-30s: Disabled or different (%s)\n", cfg, val)
		} else {
			fmt.Printf("[-] %-30s: Not set\n", cfg)
		}
	}
}
