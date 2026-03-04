# 🛡️ awhy

**awhy** is a lightweight, high-performance Linux security mitigation checker written in Go. It quickly audits your system's kernel and runtime configurations to determine if common hardening techniques are active.

![Go Version](https://img.shields.io/badge/go-%3E%3D1.16-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)

## ✨ Features

- 🚀 **Fast & Lightweight:** Zero dependencies, compiled to a single binary.
- 🌈 **Colorized Output:** Clear visual indicators (Green/Yellow/Red) for security status.
- 📋 **Comprehensive Checks:**
    - Kernel hardening (ASLR, Kptr restrict, dmesg restrict, etc.)
    - Linux Security Modules (SELinux, AppArmor)
    - File system protections (hardlinks, symlinks, FIFOs)
    - Kernel Configuration (`/proc/config.gz`) hardening options.
- ⚖️ **Stable UI:** Clever sorting keeps the interface consistent even when statuses change.
- 🐧 **Hardened Kernel Detection:** Supports custom hardened kernels like CachyOS.

## 🚀 Getting Started

### Prerequisites

- A Linux system (kernel 5.0+)
- Go 1.16 or higher (if building from source)

### Installation & Building

```bash
# Clone the repository
git clone https://github.com/euxaristia/awhy.git
cd awhy

# Build the binary
go build -o awhy main.go
```

### 💻 Usage

Run the tool to audit your system:

```bash
./awhy
```

> [!TIP]
> Running as `root` (e.g., `sudo ./awhy`) is recommended to ensure all checks (especially BPF JIT and Kernel Config) can be performed accurately.

## 📊 Example Output

```text
[+] Hardened Kernel                         : Yes (50% Hardened)
   ├── Kernel: 6.17.13-2-cachyos-hardened-lto
   ├── Confidence Score: 15/30 points (50%)
   ├── Score accounts for both boot parameters and compiled-in kernel defaults.
...
[+] ASLR                                    : Full (2)
...
[-] BPF JIT Hardening                       : Requires root
[-] NSA SELinux                             : Not found
[-] AppArmor                                : Not found
[-] GNOME HSI                               : Unavailable (fwupdtool not found)
[-] Secure Boot                             : Disabled
```

## 🧪 Testing

Run the test suite:

```bash
go test -v ./...
```

To generate a coverage report:

```bash
# Per-function coverage summary
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Visual HTML report (opens in browser, highlights tested/untested lines)
go tool cover -html=coverage.out
```

The `-coverprofile=FILE` flag records which lines of code are exercised by tests. Use `go tool cover -func` for a quick per-function breakdown, or `-html` for an interactive view that colour-codes every line red (untested) or green (tested).

## 🛠️ Contributing

Contributions are welcome! If you have ideas for new security checks or improvements to the UI, feel free to:

1. Fork the project at https://github.com/euxaristia/awhy
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

---
*Stay Hard!* 🛡️
