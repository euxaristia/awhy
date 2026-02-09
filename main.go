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

	config, configErr := getKernelConfig()

	var generalResults []Result
	generalResults = append(generalResults, checkHardenedKernel(config, configErr))
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
	generalResults = append(generalResults, checkLandlock())

	ptraceMap := map[string]string{"0": "Classic", "1": "Restricted (Child)", "2": "Admin Only", "3": "None"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/yama/ptrace_scope", "1", "Yama ptrace_scope", ptraceMap))

	boolMap := map[string]string{"0": "Disabled", "1": "Enabled"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_hardlinks", "1", "Protected Hardlinks", boolMap))
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_symlinks", "1", "Protected Symlinks", boolMap))
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_fifos", "1", "Protected FIFOs", boolMap))
	generalResults = append(generalResults, getSysctlResult("/proc/sys/fs/protected_regular", "1", "Protected Regular Files", boolMap))

	// New sysctl checks
	perfMap := map[string]string{"0": "Disabled", "1": "Restrict non-CAP_PERFMON", "2": "Restrict non-root", "3": "Fully restricted"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/perf_event_paranoid", "3", "perf_event Restrict", perfMap))

	ubpfMap := map[string]string{"0": "Allowed", "1": "Disabled for unprivileged", "2": "Disabled for all non-CAP_BPF"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/unprivileged_bpf_disabled", "2", "Unprivileged BPF Disabled", ubpfMap))

	generalResults = append(generalResults, checkKexecDisabled(config))

	iouringMap := map[string]string{"0": "Allowed", "1": "Disabled for unprivileged", "2": "Disabled for all"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/kernel/io_uring_disabled", "2", "io_uring Restrict", iouringMap))

	generalResults = append(generalResults, checkUserfaultfd(config))

	tiocMap := map[string]string{"0": "Restricted", "1": "Allowed (legacy)"}
	generalResults = append(generalResults, getSysctlResult("/proc/sys/dev/tty/legacy_tiocsti", "0", "TIOCSTI Restrict", tiocMap))

	generalResults = append(generalResults, checkSeccomp())
	generalResults = append(generalResults, checkModuleSigning(config))
	generalResults = append(generalResults, checkLockdownLSM())
	generalResults = append(generalResults, checkCoreDumpConfig())
	generalResults = append(generalResults, checkUserNamespaces(config))

	sortAndPrintResults(generalResults)

	checkKernelConfig(config, configErr)
}

func printHeader() {
	header := `
    _              __        __      _   _               _  __   __    _
   / \   _ __ ___  \ \      / /___  | | | | __ _ _ __ __| | \ \ / /__ | |_
  / _ \ | '__/ _ \  \ \ /\ / / _ \  | |_| |/ _` + "`" + ` | '__/ _` + "`" + ` |  \ V / _ \| __|
 / ___ \| | |  __/   \ V  V /  __/  |  _  | (_| | | | (_| |   | |  __/| |_
/_/   \_\_|  \___|    \_/\_/ \___|  |_| |_|\__,_|_|  \__,_|   |_|\___| \__|
`
	fmt.Printf("%s%s%s", ColorCyan, header, ColorReset)
	fmt.Printf("%sAreWeHardYet - Linux Security Mitigation Checker%s\n", ColorBold, ColorReset)
	fmt.Println("========================================================")
}

func sortAndPrintResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		// Absolute priority items
		getPriority := func(r Result) int {
			switch r.Description {
			case "Hardened Kernel":
				return 0
			case "ASLR":
				return 1
			case "BPF JIT Hardening":
				return 10
			case "NSA SELinux":
				return 11
			case "AppArmor":
				return 12
			case "Landlock LSM":
				return 13
			case "Lockdown LSM":
				return 14
			case "GNOME HSI":
				return 20
			case "Secure Boot":
				return 21
			default:
				return 5 // General checks in between
			}
		}

		pi := getPriority(results[i])
		pj := getPriority(results[j])

		if pi != pj {
			return pi < pj
		}

		if results[i].SortWeight != results[j].SortWeight {
			return results[i].SortWeight < results[j].SortWeight
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

func getSysctlResult(path string, expected string, description string, mapping map[string]string) Result {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		status := "Could not read " + path
		if isPermissionDenied(err) {
			status = "Requires root"
		} else if os.IsNotExist(err) {
			status = "Not available (sysctl not present)"
		}
		return Result{"[-]", description, status, ColorRed, 2, nil}
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

func getKernelConfig() (map[string]string, error) {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	found := make(map[string]string)
	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") && strings.HasSuffix(line, "is not set") {
			// Parse "# CONFIG_FOO is not set" as CONFIG_FOO=n
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				found[parts[1]] = "n"
			}
		} else if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			found[parts[0]] = parts[1]
		}
	}
	return found, nil
}

func checkHardenedKernel(config map[string]string, configErr error) Result {
	var subInfo []string
	score := 0
	maxScore := 0

	out, _ := exec.Command("uname", "-r").Output()
	version := strings.TrimSpace(string(out))

	// Check 0: Kernel version string indicators
	versionLower := strings.ToLower(version)
	if strings.Contains(versionLower, "hardened") {
		subInfo = append(subInfo, "Kernel version contains 'hardened' identifier (+3)")
		score += 3
	}
	if strings.Contains(versionLower, "grsec") {
		subInfo = append(subInfo, "Kernel version contains 'grsec' identifier (+5)")
		score += 5
	}
	maxScore += 5

	// Check 1: Kernel Command Line Arguments
	cmdlineBytes, err := ioutil.ReadFile("/proc/cmdline")
	if err == nil {
		cmdline := string(cmdlineBytes)
		args := strings.Fields(cmdline)

		type bootParam struct {
			points int
			desc   string
		}

		positiveArgs := map[string]bootParam{
			"slab_nomerge":                  {1, "Disables merging of slab caches"},
			"slub_debug=FZP":                {1, "Enables SLUB sanity checks (Full/Zero/Poison)"},
			"slub_debug=P":                  {1, "Enables SLUB poisoning"},
			"init_on_alloc=1":               {2, "Zeroes memory on allocation"},
			"init_on_free=1":                {2, "Zeroes memory on deallocation"},
			"page_alloc.shuffle=1":          {1, "Randomizes page allocator freelists"},
			"pti=on":                        {2, "Enables Kernel Page Table Isolation"},
			"randomize_kstack_offset=on":    {1, "Randomizes kernel stack offset per syscall"},
			"vsyscall=none":                 {2, "Disables legacy vsyscall page"},
			"debugfs=off":                   {1, "Disables debugfs mount"},
			"oops=panic":                    {1, "Panics on kernel oops (prevents exploit retry)"},
			"lockdown=confidentiality":      {4, "Lockdown: confidentiality (strongest)"},
			"lockdown=integrity":            {3, "Lockdown: integrity mode"},
			"page_poison=1":                 {1, "Enables page poisoning"},
			"spectre_v2=on":                 {1, "Forces Spectre v2 mitigation"},
			"spec_store_bypass_disable=on":  {1, "Forces Speculative Store Bypass mitigation"},
			"l1tf=full,force":               {1, "Full L1TF mitigation"},
			"mds=full,nosmt":                {1, "Full MDS mitigation with SMT disabled"},
			"mds=full":                      {1, "Full MDS mitigation"},
			"tsx=off":                       {1, "Disables Intel TSX"},
			"iommu=force":                   {1, "Forces IOMMU usage"},
			"iommu.passthrough=0":           {1, "Disables IOMMU passthrough"},
			"iommu.strict=1":                {1, "Enables strict IOMMU TLB invalidation"},
			"efi=disable_early_pci_dma":     {1, "Disables early PCI DMA (Thunderclap protection)"},
			"mitigations=auto,nosmt":        {2, "All mitigations enabled, SMT disabled"},
			"kfence.sample_interval=100":    {1, "KFENCE sampling enabled"},
			"slab_nomerge init_on_alloc=1":  {0, ""},
			"module.sig_enforce=1":          {2, "Enforces kernel module signatures"},
			"extra_latent_entropy":          {1, "Extra entropy at boot"},
		}

		negativeArgs := map[string]bootParam{
			"vsyscall=emulate":    {-2, "Uses legacy vsyscall emulation"},
			"vsyscall=native":     {-3, "Uses legacy vsyscall native (ROP gadget)"},
			"debugfs=on":          {-1, "Explicitly enables debugfs"},
			"nokaslr":             {-5, "KASLR disabled"},
			"nopti":               {-3, "Page Table Isolation disabled"},
			"nospectre_v2":        {-3, "Spectre v2 mitigations disabled"},
			"mitigations=off":     {-10, "All CPU mitigations disabled"},
			"nosmep":              {-3, "SMEP disabled"},
			"nosmap":              {-3, "SMAP disabled"},
			"noxsave":             {-1, "XSAVE disabled"},
			"no_stf_barrier":      {-2, "Store-to-forwarding barrier disabled"},
			"noibrs":              {-2, "IBRS disabled"},
			"noibpb":              {-2, "IBPB disabled"},
			"nospec_store_bypass_disable": {-2, "Speculative Store Bypass mitigation disabled"},
			"tsx=on":              {-1, "TSX explicitly enabled"},
			"iommu=off":           {-2, "IOMMU disabled"},
			"iommu.passthrough=1": {-2, "IOMMU in passthrough mode"},
		}
		maxScore += 18 // reasonable max from boot params

		for _, arg := range args {
			if bp, ok := positiveArgs[arg]; ok && bp.points > 0 {
				subInfo = append(subInfo, fmt.Sprintf("Boot: %s — %s (+%d)", arg, bp.desc, bp.points))
				score += bp.points
			}
			if bp, ok := negativeArgs[arg]; ok {
				subInfo = append(subInfo, fmt.Sprintf("Weak: %s — %s (%d)", arg, bp.desc, bp.points))
				score += bp.points
			}
		}
	}

	// Check 2: Kernel Configuration (Compiled-in hardening)
	if config != nil {
		type configCheck struct {
			points int
			desc   string
		}

		// Configs that SHOULD be enabled
		hardeningConfigs := map[string]configCheck{
			// Memory hardening
			"CONFIG_INIT_ON_ALLOC_DEFAULT_ON":    {2, "Zero-fill on heap allocation"},
			"CONFIG_INIT_ON_FREE_DEFAULT_ON":     {2, "Zero-fill on heap free"},
			"CONFIG_HARDENED_USERCOPY":           {2, "Validates usercopy buffer sizes"},
			"CONFIG_FORTIFY_SOURCE":              {2, "Compile-time + runtime buffer overflow checks"},
			"CONFIG_SLAB_FREELIST_RANDOM":        {1, "SLAB freelist randomization"},
			"CONFIG_SLAB_FREELIST_HARDENED":      {2, "SLAB freelist pointer mangling"},
			"CONFIG_LIST_HARDENED":               {1, "Hardened linked list integrity checks"},
			"CONFIG_SHUFFLE_PAGE_ALLOCATOR":      {1, "Page allocator freelist randomization"},
			"CONFIG_VMAP_STACK":                  {2, "Virtually-mapped kernel stacks (guard pages)"},
			"CONFIG_STACKPROTECTOR_STRONG":       {2, "Stack canaries (strong variant)"},
			"CONFIG_THREAD_INFO_IN_TASK":         {1, "thread_info in task_struct (not on stack)"},
			"CONFIG_BUG_ON_DATA_CORRUPTION":      {1, "Panic on detected data corruption"},
			"CONFIG_KFENCE":                      {1, "Kernel Electric Fence (sampling heap guard)"},
			"CONFIG_ZERO_CALL_USED_REGS":         {2, "Zero caller-used registers on function return"},
			// Exploit mitigations
			"CONFIG_RANDOMIZE_BASE":              {2, "KASLR (Kernel Address Space Layout Randomization)"},
			"CONFIG_RANDOMIZE_MEMORY":            {1, "Randomize kernel memory sections"},
			"CONFIG_RANDOMIZE_KSTACK_OFFSET":     {1, "Kernel stack offset randomization support"},
			"CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT": {2, "Kernel stack offset randomization default on"},
			"CONFIG_PAGE_TABLE_ISOLATION":        {2, "Kernel Page Table Isolation (Meltdown)"},
			"CONFIG_RETPOLINE":                   {1, "Retpoline (Spectre v2)"},
			"CONFIG_X86_KERNEL_IBT":              {2, "Indirect Branch Tracking (CET-IBT)"},
			"CONFIG_LEGACY_VSYSCALL_NONE":        {2, "No legacy vsyscall page (removes ROP gadgets)"},
			"CONFIG_STRICT_KERNEL_RWX":           {1, "Kernel text/rodata marked read-only/no-execute"},
			"CONFIG_STRICT_MODULE_RWX":           {1, "Module text/rodata marked read-only/no-execute"},
			"CONFIG_SCHED_STACK_END_CHECK":       {1, "Stack end canary check on schedule"},
			"CONFIG_GCC_PLUGIN_STACKLEAK":        {2, "STACKLEAK plugin (erase stack on syscall return)"},
			"CONFIG_IOMMU_DEFAULT_DMA_STRICT":    {2, "Strict IOMMU DMA translation (DMA attack protection)"},
			// Module security
			"CONFIG_MODULE_SIG":                  {2, "Kernel module signature verification"},
			"CONFIG_MODULE_SIG_ALL":              {1, "Sign all modules during build"},
			"CONFIG_MODULE_SIG_SHA512":           {1, "Module signing with SHA-512"},
			// Seccomp
			"CONFIG_SECCOMP":                     {1, "Seccomp system call filtering support"},
			"CONFIG_SECCOMP_FILTER":              {2, "Seccomp BPF filter support"},
			// LSM support
			"CONFIG_SECURITY_YAMA":               {1, "Yama LSM (ptrace restrictions)"},
			"CONFIG_SECURITY_LANDLOCK":           {1, "Landlock LSM (unprivileged sandboxing)"},
			"CONFIG_SECURITY_LOCKDOWN_LSM":       {1, "Lockdown LSM support"},
			"CONFIG_SECURITY_LOADPIN":            {1, "LoadPin LSM (trusted filesystem enforcement)"},
			// Debugging integrity checks (defense in depth)
			"CONFIG_DEBUG_LIST":                  {1, "Linked list manipulation integrity checks"},
			"CONFIG_DEBUG_NOTIFIERS":             {1, "Notifier call chain integrity checks"},
			"CONFIG_DEBUG_SG":                    {1, "Scatter-gather table integrity checks"},
			// Network hardening
			"CONFIG_SYN_COOKIES":                 {1, "TCP SYN cookie support (SYN flood protection)"},
			// Misc hardening
			"CONFIG_SECURITY_DMESG_RESTRICT":     {1, "Restrict dmesg to CAP_SYSLOG by default"},
			"CONFIG_SECURITY_PERF_EVENTS_RESTRICT": {1, "Restrict perf events to CAP_PERFMON"},
			"CONFIG_SECURITY_TIOCSTI_RESTRICT":   {1, "Restrict TIOCSTI ioctl (terminal injection)"},
			"CONFIG_HARDENED_USERCOPY_DEFAULT_ON": {1, "Hardened usercopy enabled by default"},
		}

		// Configs that SHOULD be disabled (presence = weakness)
		dangerousConfigs := map[string]configCheck{
			"CONFIG_DEVMEM":                   {-2, "Allows raw physical memory access from userspace"},
			"CONFIG_PROC_KCORE":               {-1, "Exposes kernel memory via /proc/kcore"},
			"CONFIG_KEXEC":                    {-1, "Allows loading a new kernel (bypass Secure Boot)"},
			"CONFIG_KEXEC_FILE":               {-1, "Allows loading a new kernel via file"},
			"CONFIG_HIBERNATION":              {-1, "Hibernation can expose memory contents"},
			"CONFIG_COMPAT_VDSO":              {-1, "Legacy 32-bit vDSO (predictable mapping)"},
			"CONFIG_MODIFY_LDT_SYSCALL":       {-1, "modify_ldt syscall (16-bit compat, exploit vector)"},
			"CONFIG_LDISC_AUTOLOAD":           {-1, "Auto-loads line disciplines (attack surface)"},
			"CONFIG_USERFAULTFD":              {-1, "userfaultfd (use-after-free exploit primitive)"},
			"CONFIG_USER_NS_UNPRIVILEGED":     {-1, "Unprivileged user namespaces (privilege escalation vector)"},
			"CONFIG_IOMMU_DEFAULT_PASSTHROUGH": {-2, "IOMMU passthrough (no DMA protection)"},
			"CONFIG_PROFILING":                {-1, "Profiling support (information exposure)"},
		}

		enabledCount := 0
		for cfg, cc := range hardeningConfigs {
			maxScore += cc.points
			if val, ok := config[cfg]; ok && (val == "y" || val == "1") {
				subInfo = append(subInfo, fmt.Sprintf("Config: %s=y — %s (+%d)", cfg, cc.desc, cc.points))
				score += cc.points
				enabledCount++
			}
		}

		for cfg, cc := range dangerousConfigs {
			if val, ok := config[cfg]; ok && (val == "y" || val == "1") {
				subInfo = append(subInfo, fmt.Sprintf("Weak config: %s=y — %s (%d)", cfg, cc.desc, cc.points))
				score += cc.points
			}
		}
	} else {
		msg := "Kernel config unavailable for analysis (/proc/config.gz missing)"
		if configErr != nil && isPermissionDenied(configErr) {
			msg = "Kernel config analysis requires root privileges"
		}
		subInfo = append(subInfo, msg)
		maxScore += 50
	}

	// Check 3: Lockdown Mode
	lockdownBytes, err := ioutil.ReadFile("/sys/kernel/security/lockdown")
	if err == nil {
		lockdownContent := string(lockdownBytes)
		maxScore += 4
		if strings.Contains(lockdownContent, "[confidentiality]") {
			subInfo = append(subInfo, "Lockdown mode: confidentiality (+4)")
			score += 4
		} else if strings.Contains(lockdownContent, "[integrity]") {
			subInfo = append(subInfo, "Lockdown mode: integrity (+3)")
			score += 3
		} else if strings.Contains(lockdownContent, "[none]") {
			subInfo = append(subInfo, "Lockdown mode: none (not active)")
		}
	}

	// Check 4: PaX / Grsecurity
	maxScore += 5
	if _, err := os.Stat("/proc/sys/kernel/pax"); err == nil {
		subInfo = append(subInfo, "PaX sysctl directory detected (+5)")
		score += 5
	}
	if _, err := os.Stat("/proc/sys/kernel/grsecurity"); err == nil {
		subInfo = append(subInfo, "Grsecurity sysctl directory detected (+5)")
		score += 5
	}

	// Ensure maxScore is at least 1
	if maxScore < 1 {
		maxScore = 1
	}

	percentage := (score * 100) / maxScore
	if percentage > 100 {
		percentage = 100
	}
	if percentage < 0 {
		percentage = 0
	}

	status := fmt.Sprintf("No (%d%% Hardened)", percentage)
	color := ColorRed
	weight := 2

	if percentage >= 50 {
		status = fmt.Sprintf("Yes (%d%% Hardened)", percentage)
		color = ColorGreen
		weight = 0
	} else if percentage >= 20 {
		status = fmt.Sprintf("Partial (%d%% Hardened)", percentage)
		color = ColorYellow
		weight = 1
	}

	subInfo = append([]string{
		fmt.Sprintf("Kernel: %s", version),
		fmt.Sprintf("Confidence Score: %d/%d points (%d%%)", score, maxScore, percentage),
		"Score accounts for boot parameters, compiled-in kernel hardening, and runtime state.",
	}, subInfo...)

	return Result{getPrefix(weight), "Hardened Kernel", status, color, weight, subInfo}
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
		if err != nil {
			status := "Present"
			if isPermissionDenied(err) {
				status = "Requires root"
			}
			return Result{"[+]", "NSA SELinux", status, ColorGreen, 0, nil}
		}
		if strings.TrimSpace(string(content)) == "1" {
			return Result{"[+]", "NSA SELinux", "Enabled (Enforcing)", ColorGreen, 0, nil}
		} else {
			return Result{"[!]", "NSA SELinux", "Enabled (Permissive)", ColorYellow, 1, nil}
		}
	}
	return Result{"[-]", "NSA SELinux", "Not found", ColorRed, 2, nil}
}

func checkAppArmor() Result {
	_, err := os.Stat("/sys/kernel/security/apparmor")
	if err == nil {
		content, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err != nil {
			status := "Present"
			if isPermissionDenied(err) {
				status = "Requires root"
			}
			return Result{"[!]", "AppArmor", status, ColorYellow, 1, nil}
		}
		if strings.TrimSpace(string(content)) == "Y" {
			return Result{"[+]", "AppArmor", "Enabled", ColorGreen, 0, nil}
		} else {
			return Result{"[!]", "AppArmor", "Present but disabled", ColorYellow, 1, nil}
		}
	}
	return Result{"[-]", "AppArmor", "Not found", ColorRed, 2, nil}
}

func checkLandlock() Result {
	_, err := os.Stat("/sys/kernel/security/landlock")
	if err == nil {
		// Check ABI version
		content, err := ioutil.ReadFile("/sys/kernel/security/landlock/abi_version")
		if err == nil {
			ver := strings.TrimSpace(string(content))
			return Result{"[+]", "Landlock LSM", fmt.Sprintf("Enabled (ABI v%s)", ver), ColorGreen, 0, nil}
		}
		return Result{"[+]", "Landlock LSM", "Enabled", ColorGreen, 0, nil}
	}
	// Check if compiled in but not active
	lsmBytes, _ := ioutil.ReadFile("/sys/kernel/security/lsm")
	if lsmBytes != nil && strings.Contains(string(lsmBytes), "landlock") {
		return Result{"[+]", "Landlock LSM", "Active", ColorGreen, 0, nil}
	}
	return Result{"[-]", "Landlock LSM", "Not available", ColorRed, 2, nil}
}

func checkLockdownLSM() Result {
	content, err := ioutil.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		if isPermissionDenied(err) {
			return Result{"[-]", "Lockdown LSM", "Requires root", ColorRed, 2, nil}
		}
		return Result{"[-]", "Lockdown LSM", "Not available", ColorRed, 2, nil}
	}
	lockdown := strings.TrimSpace(string(content))
	if strings.Contains(lockdown, "[confidentiality]") {
		return Result{"[+]", "Lockdown LSM", "Confidentiality mode", ColorGreen, 0, nil}
	} else if strings.Contains(lockdown, "[integrity]") {
		return Result{"[+]", "Lockdown LSM", "Integrity mode", ColorGreen, 0, nil}
	}
	return Result{"[!]", "Lockdown LSM", fmt.Sprintf("None (%s)", lockdown), ColorYellow, 1, nil}
}

func checkSeccomp() Result {
	content, err := ioutil.ReadFile("/proc/sys/kernel/seccomp/actions_avail")
	if err == nil {
		actions := strings.TrimSpace(string(content))
		return Result{"[+]", "Seccomp", fmt.Sprintf("Available (%s)", actions), ColorGreen, 0, nil}
	}
	// Fallback: check boot config
	if _, err := os.Stat("/proc/1/status"); err == nil {
		statusBytes, err := ioutil.ReadFile("/proc/1/status")
		if err == nil && strings.Contains(string(statusBytes), "Seccomp:") {
			return Result{"[+]", "Seccomp", "Available (detected via /proc)", ColorGreen, 0, nil}
		}
	}
	return Result{"[-]", "Seccomp", "Not available", ColorRed, 2, nil}
}

func checkModuleSigning(config map[string]string) Result {
	if config == nil {
		return Result{"[-]", "Module Signing", "Requires /proc/config.gz", ColorRed, 2, nil}
	}

	sigEnabled := config["CONFIG_MODULE_SIG"] == "y"
	sigForce := config["CONFIG_MODULE_SIG_FORCE"] == "y"
	sigHash := config["CONFIG_MODULE_SIG_HASH"]

	if !sigEnabled {
		return Result{"[-]", "Module Signing", "Not enabled", ColorRed, 2, nil}
	}

	var subInfo []string
	if sigHash != "" {
		subInfo = append(subInfo, fmt.Sprintf("Hash algorithm: %s", strings.Trim(sigHash, "\"")))
	}

	keyType := "RSA"
	if config["CONFIG_MODULE_SIG_KEY_TYPE_ECDSA"] == "y" {
		keyType = "ECDSA"
	}
	subInfo = append(subInfo, fmt.Sprintf("Key type: %s", keyType))

	if sigForce {
		subInfo = append(subInfo, "Enforcement: mandatory (unsigned modules rejected)")
		return Result{"[+]", "Module Signing", "Enforced", ColorGreen, 0, subInfo}
	}

	subInfo = append(subInfo, "Enforcement: optional (unsigned modules allowed with taint)")
	return Result{"[!]", "Module Signing", "Enabled (not enforced)", ColorYellow, 1, subInfo}
}

func checkCoreDumpConfig() Result {
	// Check core_pattern
	content, err := ioutil.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		return Result{"[-]", "Core Dump Restrict", "Could not check", ColorRed, 2, nil}
	}
	pattern := strings.TrimSpace(string(content))

	// Check if core dumps are piped to a handler or disabled
	var subInfo []string
	subInfo = append(subInfo, fmt.Sprintf("core_pattern: %s", pattern))

	// Check RLIMIT via /proc/self/limits
	limitsBytes, err := ioutil.ReadFile("/proc/self/limits")
	if err == nil {
		for _, line := range strings.Split(string(limitsBytes), "\n") {
			if strings.HasPrefix(line, "Max core file size") {
				fields := strings.Fields(line)
				// The format is: "Max core file size    <soft>    <hard>    <units>"
				for i, f := range fields {
					if f == "size" && i+1 < len(fields) {
						softLimit := fields[i+1]
						subInfo = append(subInfo, fmt.Sprintf("Soft limit: %s", softLimit))
						if softLimit == "0" {
							return Result{"[+]", "Core Dump Restrict", "Disabled (limit=0)", ColorGreen, 0, subInfo}
						}
					}
				}
			}
		}
	}

	if strings.HasPrefix(pattern, "|") {
		subInfo = append(subInfo, "Core dumps piped to handler")
		return Result{"[!]", "Core Dump Restrict", "Piped to handler", ColorYellow, 1, subInfo}
	}

	return Result{"[!]", "Core Dump Restrict", "Enabled", ColorYellow, 1, subInfo}
}

func checkUserNamespaces(config map[string]string) Result {
	var subInfo []string

	// Check unprivileged user namespace clone sysctl (Debian/Ubuntu)
	content, err := ioutil.ReadFile("/proc/sys/kernel/unprivileged_userns_clone")
	if err == nil {
		val := strings.TrimSpace(string(content))
		if val == "0" {
			subInfo = append(subInfo, "unprivileged_userns_clone=0 (restricted)")
			return Result{"[+]", "User Namespace Restrict", "Restricted", ColorGreen, 0, subInfo}
		}
		subInfo = append(subInfo, fmt.Sprintf("unprivileged_userns_clone=%s", val))
	}

	// Check max_user_namespaces
	content, err = ioutil.ReadFile("/proc/sys/user/max_user_namespaces")
	if err == nil {
		val := strings.TrimSpace(string(content))
		subInfo = append(subInfo, fmt.Sprintf("max_user_namespaces=%s", val))
		if val == "0" {
			return Result{"[+]", "User Namespace Restrict", "Disabled (max=0)", ColorGreen, 0, subInfo}
		}
	}

	// Check kernel config
	if config != nil {
		if config["CONFIG_USER_NS_UNPRIVILEGED"] == "n" {
			subInfo = append(subInfo, "CONFIG_USER_NS_UNPRIVILEGED is not set (restricted at compile time)")
			return Result{"[+]", "User Namespace Restrict", "Compile-time restricted", ColorGreen, 0, subInfo}
		}
		if config["CONFIG_USER_NS"] == "y" && config["CONFIG_USER_NS_UNPRIVILEGED"] != "n" {
			subInfo = append(subInfo, "User namespaces enabled, unprivileged access allowed")
			return Result{"[!]", "User Namespace Restrict", "Unrestricted", ColorYellow, 1, subInfo}
		}
	}

	if len(subInfo) > 0 {
		return Result{"[!]", "User Namespace Restrict", "Partially restricted", ColorYellow, 1, subInfo}
	}
	return Result{"[-]", "User Namespace Restrict", "Could not determine", ColorRed, 2, nil}
}

func checkKexecDisabled(config map[string]string) Result {
	content, err := ioutil.ReadFile("/proc/sys/kernel/kexec_load_disabled")
	if err == nil {
		val := strings.TrimSpace(string(content))
		if val == "1" {
			return Result{"[+]", "kexec_load Disabled", "Disabled (1)", ColorGreen, 0, nil}
		}
		return Result{"[!]", "kexec_load Disabled", "Allowed (0)", ColorYellow, 1, nil}
	}
	// Sysctl missing — check if kexec was compiled out entirely (best outcome)
	if config != nil {
		if config["CONFIG_KEXEC"] != "y" && config["CONFIG_KEXEC_FILE"] != "y" {
			return Result{"[+]", "kexec_load Disabled", "Not compiled in (CONFIG_KEXEC not set)", ColorGreen, 0, nil}
		}
	}
	if isPermissionDenied(err) {
		return Result{"[-]", "kexec_load Disabled", "Requires root", ColorRed, 2, nil}
	}
	return Result{"[-]", "kexec_load Disabled", "Could not determine", ColorRed, 2, nil}
}

func checkUserfaultfd(config map[string]string) Result {
	content, err := ioutil.ReadFile("/proc/sys/vm/unprivileged_userfaultfd")
	if err == nil {
		val := strings.TrimSpace(string(content))
		if val == "0" {
			return Result{"[+]", "Unprivileged userfaultfd", "Restricted (0)", ColorGreen, 0, nil}
		}
		return Result{"[!]", "Unprivileged userfaultfd", "Allowed (1)", ColorYellow, 1, nil}
	}
	// Sysctl missing — check if userfaultfd was compiled out entirely (best outcome)
	if config != nil {
		if config["CONFIG_USERFAULTFD"] != "y" {
			return Result{"[+]", "Unprivileged userfaultfd", "Not compiled in (CONFIG_USERFAULTFD not set)", ColorGreen, 0, nil}
		}
	}
	if isPermissionDenied(err) {
		return Result{"[-]", "Unprivileged userfaultfd", "Requires root", ColorRed, 2, nil}
	}
	return Result{"[-]", "Unprivileged userfaultfd", "Could not determine", ColorRed, 2, nil}
}

func checkKernelConfig(found map[string]string, configErr error) {
	if found == nil {
		fmt.Printf("\n%sKernel Configuration Hardening:%s\n", ColorCyan, ColorReset)
		fmt.Println("-------------------------------")
		status := "Could not read /proc/config.gz"
		if configErr != nil && isPermissionDenied(configErr) {
			status = "Requires root"
		}
		fmt.Printf("%s[-] %-40s: %s%s\n", ColorRed, "Kernel Config Checks", status, ColorReset)
		return
	}

	type configCategory struct {
		name    string
		configs []struct {
			key      string
			expected string
			desc     string
		}
	}

	categories := []configCategory{
		{
			name: "Memory Hardening",
			configs: []struct {
				key      string
				expected string
				desc     string
			}{
				{"CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "y", "Zero-fill heap on alloc"},
				{"CONFIG_INIT_ON_FREE_DEFAULT_ON", "y", "Zero-fill heap on free"},
				{"CONFIG_HARDENED_USERCOPY", "y", "Bounds-check usercopy"},
				{"CONFIG_HARDENED_USERCOPY_DEFAULT_ON", "y", "Usercopy hardening default on"},
				{"CONFIG_FORTIFY_SOURCE", "y", "FORTIFY_SOURCE overflow checks"},
				{"CONFIG_SLAB_FREELIST_RANDOM", "y", "SLAB freelist randomization"},
				{"CONFIG_SLAB_FREELIST_HARDENED", "y", "SLAB freelist pointer mangling"},
				{"CONFIG_LIST_HARDENED", "y", "Linked list integrity checks"},
				{"CONFIG_SHUFFLE_PAGE_ALLOCATOR", "y", "Page allocator randomization"},
				{"CONFIG_VMAP_STACK", "y", "Virtually-mapped stacks"},
				{"CONFIG_STACKPROTECTOR_STRONG", "y", "Stack canaries (strong)"},
				{"CONFIG_THREAD_INFO_IN_TASK", "y", "thread_info in task_struct"},
				{"CONFIG_KFENCE", "y", "Kernel Electric Fence"},
				{"CONFIG_ZERO_CALL_USED_REGS", "y", "Zero caller-used registers"},
				{"CONFIG_BUG_ON_DATA_CORRUPTION", "y", "Panic on data corruption"},
			},
		},
		{
			name: "Exploit Mitigations",
			configs: []struct {
				key      string
				expected string
				desc     string
			}{
				{"CONFIG_RANDOMIZE_BASE", "y", "KASLR"},
				{"CONFIG_RANDOMIZE_MEMORY", "y", "Memory section randomization"},
				{"CONFIG_RANDOMIZE_KSTACK_OFFSET", "y", "Stack offset randomization support"},
				{"CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT", "y", "Stack offset randomization default on"},
				{"CONFIG_PAGE_TABLE_ISOLATION", "y", "KPTI (Meltdown mitigation)"},
				{"CONFIG_RETPOLINE", "y", "Retpoline (Spectre v2)"},
				{"CONFIG_X86_KERNEL_IBT", "y", "Indirect Branch Tracking (CET-IBT)"},
				{"CONFIG_LEGACY_VSYSCALL_NONE", "y", "No legacy vsyscall page"},
				{"CONFIG_STRICT_KERNEL_RWX", "y", "Kernel text read-only/no-exec"},
				{"CONFIG_STRICT_MODULE_RWX", "y", "Module text read-only/no-exec"},
				{"CONFIG_SCHED_STACK_END_CHECK", "y", "Stack end canary on schedule"},
				{"CONFIG_GCC_PLUGIN_STACKLEAK", "y", "STACKLEAK plugin"},
			},
		},
		{
			name: "Module Security",
			configs: []struct {
				key      string
				expected string
				desc     string
			}{
				{"CONFIG_MODULE_SIG", "y", "Module signature verification"},
				{"CONFIG_MODULE_SIG_FORCE", "y", "Enforce module signatures"},
				{"CONFIG_MODULE_SIG_ALL", "y", "Sign all modules at build"},
				{"CONFIG_MODULE_SIG_SHA512", "y", "SHA-512 module signing"},
			},
		},
		{
			name: "LSM & Access Control",
			configs: []struct {
				key      string
				expected string
				desc     string
			}{
				{"CONFIG_SECURITY", "y", "Security subsystem"},
				{"CONFIG_SECURITY_YAMA", "y", "Yama LSM"},
				{"CONFIG_SECURITY_LANDLOCK", "y", "Landlock LSM"},
				{"CONFIG_SECURITY_LOCKDOWN_LSM", "y", "Lockdown LSM"},
				{"CONFIG_SECURITY_LOADPIN", "y", "LoadPin LSM"},
				{"CONFIG_SECURITY_SAFESETID", "y", "SafeSetID LSM"},
				{"CONFIG_SECURITY_APPARMOR", "y", "AppArmor LSM"},
				{"CONFIG_SECURITY_SELINUX", "y", "SELinux LSM"},
				{"CONFIG_SECCOMP", "y", "Seccomp support"},
				{"CONFIG_SECCOMP_FILTER", "y", "Seccomp BPF filter"},
			},
		},
		{
			name: "DMA & Hardware Protection",
			configs: []struct {
				key      string
				expected string
				desc     string
			}{
				{"CONFIG_IOMMU_SUPPORT", "y", "IOMMU support"},
				{"CONFIG_IOMMU_DEFAULT_DMA_STRICT", "y", "Strict IOMMU DMA translation"},
			},
		},
		{
			name: "Network Hardening",
			configs: []struct {
				key      string
				expected string
				desc     string
			}{
				{"CONFIG_SYN_COOKIES", "y", "TCP SYN cookies"},
			},
		},
		{
			name: "Misc Hardening",
			configs: []struct {
				key      string
				expected string
				desc     string
			}{
				{"CONFIG_SECURITY_DMESG_RESTRICT", "y", "dmesg restricted by default"},
				{"CONFIG_SECURITY_PERF_EVENTS_RESTRICT", "y", "perf events restricted"},
				{"CONFIG_SECURITY_TIOCSTI_RESTRICT", "y", "TIOCSTI ioctl restricted"},
				{"CONFIG_DEBUG_LIST", "y", "List manipulation integrity"},
				{"CONFIG_DEBUG_NOTIFIERS", "y", "Notifier chain integrity"},
				{"CONFIG_DEBUG_SG", "y", "Scatter-gather integrity"},
			},
		},
	}

	// Attack surface reduction (should NOT be set)
	type negConfig struct {
		key  string
		desc string
	}
	attackSurface := []negConfig{
		{"CONFIG_DEVMEM", "Raw physical memory access (/dev/mem)"},
		{"CONFIG_PROC_KCORE", "Kernel memory via /proc/kcore"},
		{"CONFIG_KEXEC", "kexec (bypass Secure Boot)"},
		{"CONFIG_KEXEC_FILE", "kexec via file descriptor"},
		{"CONFIG_HIBERNATION", "Hibernation (memory image to disk)"},
		{"CONFIG_COMPAT_VDSO", "32-bit compat vDSO (predictable mapping)"},
		{"CONFIG_MODIFY_LDT_SYSCALL", "modify_ldt syscall (16-bit compat)"},
		{"CONFIG_LDISC_AUTOLOAD", "Line discipline auto-loading"},
		{"CONFIG_USERFAULTFD", "userfaultfd (exploit primitive)"},
		{"CONFIG_USER_NS_UNPRIVILEGED", "Unprivileged user namespaces"},
		{"CONFIG_IOMMU_DEFAULT_PASSTHROUGH", "IOMMU passthrough (no DMA protection)"},
		{"CONFIG_PROFILING", "Profiling support"},
	}

	for _, cat := range categories {
		fmt.Printf("\n%s%s:%s\n", ColorCyan, cat.name, ColorReset)
		fmt.Println(strings.Repeat("-", len(cat.name)+1))
		var results []Result
		for _, cfg := range cat.configs {
			val, ok := found[cfg.key]
			if ok && val == cfg.expected {
				results = append(results, Result{"[+]", cfg.key, fmt.Sprintf("Enabled — %s", cfg.desc), ColorGreen, 0, nil})
			} else if ok && val != "n" {
				results = append(results, Result{"[!]", cfg.key, fmt.Sprintf("Set to '%s' — %s", val, cfg.desc), ColorYellow, 1, nil})
			} else {
				results = append(results, Result{"[-]", cfg.key, fmt.Sprintf("Not set — %s", cfg.desc), ColorRed, 2, nil})
			}
		}
		sortAndPrintResults(results)
	}

	// Attack Surface Reduction
	fmt.Printf("\n%sAttack Surface Reduction (should be disabled):%s\n", ColorCyan, ColorReset)
	fmt.Println("----------------------------------------------")
	var asResults []Result
	for _, cfg := range attackSurface {
		val, ok := found[cfg.key]
		if !ok || val == "n" {
			asResults = append(asResults, Result{"[+]", cfg.key, fmt.Sprintf("Not set — %s", cfg.desc), ColorGreen, 0, nil})
		} else if val == "y" || val == "1" {
			asResults = append(asResults, Result{"[-]", cfg.key, fmt.Sprintf("Enabled — %s", cfg.desc), ColorRed, 2, nil})
		} else {
			asResults = append(asResults, Result{"[!]", cfg.key, fmt.Sprintf("Set to '%s' — %s", val, cfg.desc), ColorYellow, 1, nil})
		}
	}
	sortAndPrintResults(asResults)
}

func checkSecureBoot() Result {
	path := "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if _, err := os.Stat("/sys/firmware/efi"); os.IsNotExist(err) {
			return Result{"[-]", "Secure Boot", "Not available (Legacy BIOS?)", ColorRed, 2, nil}
		}
		status := "Unknown (Could not read efivar)"
		if isPermissionDenied(err) {
			status = "Requires root"
		}
		return Result{"[?]", "Secure Boot", status, ColorYellow, 1, nil}
	}
	// First 4 bytes are attributes, 5th byte is value.
	if len(data) >= 5 && data[4] == 1 {
		return Result{"[+]", "Secure Boot", "Enabled", ColorGreen, 0, nil}
	}
	return Result{"[-]", "Secure Boot", "Disabled", ColorRed, 2, nil}
}

func isPermissionDenied(err error) bool {
	return os.IsPermission(err)
}

func checkKernelTaint() Result {
	content, err := ioutil.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		status := "Unknown (Could not read /proc/sys/kernel/tainted)"
		if isPermissionDenied(err) {
			status = "Requires root"
		}
		return Result{"[?]", "Kernel Integrity", status, ColorRed, 2, nil}
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
	if err != nil {
		if isPermissionDenied(err) {
			subInfo = append(subInfo, "Module analysis requires root privileges")
		}
	} else {
		lines := strings.Split(string(modulesBytes), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				modName := fields[0]
				// Check for known proprietary/out-of-tree modules
				if modName == "nvidia" || modName == "nvidia_drm" || modName == "nvidia_uvm" || modName == "nvidia_modeset" ||
					modName == "vboxdrv" || modName == "vboxnetflt" || modName == "vboxnetadp" ||
					modName == "zfs" || modName == "wl" || modName == "broadcom_wl" {
					subInfo = append(subInfo, fmt.Sprintf("Potential taint source: %s", modName))
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
		return Result{"[?]", "GNOME HSI", "Tool found but not implemented", ColorYellow, 1, []string{"fwupdtool is present at " + path}}
	}

	return Result{"[-]", "GNOME HSI", "Unavailable (fwupdtool not found)", ColorRed, 2, nil}
}
