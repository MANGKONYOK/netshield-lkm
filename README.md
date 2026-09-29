# NetShield-LKM: In-Kernel Network Packet Filter

[![Linux Kernel](https://img.shields.io/badge/Linux_Kernel-5.x_%7C_6.x_%7C_7.x-blue.svg)](https://kernel.org)
[![Architecture](https://img.shields.io/badge/Architecture-x86--64-orange.svg)](https://en.wikipedia.org/wiki/X86-64)
[![Course](https://img.shields.io/badge/KMUTT-CPE_333_Operating_Systems-red.svg)](https://www.cpe.kmutt.ac.th)
[![License](https://img.shields.io/badge/License-GPL_v2-green.svg)](LICENSE)
[![Verification](https://img.shields.io/badge/Test_Suite-100%25_Passed-brightgreen.svg)](#empirical-verification-matrix)

An advanced, lightweight, in-kernel network packet filter implemented as a Linux **Loadable Kernel Module (LKM)** utilizing the **Netfilter** framework at the `NF_INET_LOCAL_IN` hook stage. Engineered under a strict **Zero-Panic Policy** for line-rate, low-latency packet inspection with built-in administrative anti-lockout fail-safes.

Developed for **CPE 333 Operating Systems**, Department of Computer Engineering, King Mongkut's University of Technology Thonburi (KMUTT).

---

## Table of Contents

- [Key Features](#key-features)
- [Packet Processing Flowchart](#packet-processing-flowchart)
- [Repository Architecture](#repository-architecture)
- [Module Parameters](#module-parameters)
- [Build & Quick Start](#build--quick-start)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Compilation](#2-compilation)
  - [3. Loading the Module](#3-loading-the-module)
  - [4. Dynamic Sysfs Reconfiguration](#4-dynamic-sysfs-reconfiguration)
  - [5. Automated Test Suite](#5-automated-test-suite)
  - [6. Unloading the Module](#6-unloading-the-module)
- [Empirical Verification Matrix](#empirical-verification-matrix)
- [Technical Documentation & Word Report](#technical-documentation--word-report)
  - [Compiling the Report (.docx)](#compiling-the-report-docx)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [Author & License](#author--license)

---

## Key Features

- **In-Kernel Line-Rate Filtering (Ring 0):** Intercepts datagrams directly within supervisor mode at `NF_INET_LOCAL_IN` (Priority: `NF_IP_PRI_FIRST`) prior to user-space socket dispatch, completely bypassing context-switch penalties and `copy_to_user()` overhead.
- **Zero-Panic Memory Safety:** Comprehensive packet bounds checking, defensive NULL pointer validation, and extraction of transport headers via `skb_header_pointer()` across non-linear socket buffers (`struct sk_buff`).
- **Administrative Anti-Lockout Fail-Safes:**
  - **SSH Protection:** Hardcoded bypass for TCP Port 22 (source and destination) guarantees remote management sessions are never severed—even if `block_port=22` or a blacklisted IP is configured.
  - **Loopback Isolation:** Default exemption for loopback (`lo`) traffic preserves Inter-Process Communication (IPC), with an optional `allow_loopback_filter` parameter for local test suites.
  - **Fail-Open Policy:** Datagrams with truncated headers, malformed buffers, or unrecognized protocols return `NF_ACCEPT`.
- **Dynamic Sysfs Control:** Real-time parameter tuning through `/sys/module/netshield/parameters/` or at insertion time via `insmod`.
- **Log Flooding and Anti-DoS Defense:** Drop notifications are throttled using `net_ratelimit()` to prevent `/var/log/kern.log` disk space exhaustion and kernel ring buffer spam.
- **Automated Verification Harness:** Includes a 7-stage automated bash test suite verifying ICMP drops, TCP port blocking, SSH bypass, sysfs state transitions and `dmesg` auditing with clean lifecycle traps.

---

## Packet Processing Flowchart

```mermaid
flowchart TD
    Start([Packet Ingress at NF_INET_LOCAL_IN]) --> CheckSKB{skb != NULL?}
    
    CheckSKB -- No --> VerdictAccept[NF_ACCEPT: Fail-Open]
    CheckSKB -- Yes --> CheckLoopback{Interface == 'lo' AND allow_loopback == false?}
    
    CheckLoopback -- Yes --> VerdictAccept
    CheckLoopback -- No --> CheckIPLen{skb->len >= sizeof(struct iphdr)?}
    
    CheckIPLen -- No --> VerdictAccept
    CheckIPLen -- Yes --> CheckIPH{iph != NULL AND iph->ihl >= 5?}
    
    CheckIPH -- No --> VerdictAccept
    CheckIPH -- Yes --> CheckTotalLen{skb->len >= iph->ihl*4 AND ntohs(tot_len) >= iph->ihl*4?}
    
    CheckTotalLen -- No --> VerdictAccept
    CheckTotalLen -- Yes --> CheckSSH{Protocol == TCP AND (sport==22 OR dport==22)?}
    
    CheckSSH -- Yes --> VerdictAccept
    CheckSSH -- No --> CheckBlacklist{blacklist_ip configured AND iph->saddr == blocked_ip?}
    
    CheckBlacklist -- Yes --> LogBlacklist[LOG_DROP_RATELIMITED: Blacklist Drop]
    LogBlacklist --> VerdictDrop[NF_DROP]
    
    CheckBlacklist -- No --> CheckICMP{drop_icmp == true AND Protocol == ICMP?}
    
    CheckICMP -- Yes --> ExtractICMP{skb_header_pointer for icmphdr valid?}
    ExtractICMP -- No --> VerdictAccept
    ExtractICMP -- Yes --> CheckEcho{icmph->type == ICMP_ECHO?}
    CheckEcho -- Yes --> LogICMP[LOG_DROP_RATELIMITED: ICMP Echo Drop]
    LogICMP --> VerdictDrop
    CheckEcho -- No --> CheckTCP
    
    CheckICMP -- No --> CheckTCP{block_port > 0 AND Protocol == TCP?}
    
    CheckTCP -- Yes --> ExtractTCP{skb_header_pointer for tcphdr valid?}
    ExtractTCP -- No --> VerdictAccept
    ExtractTCP -- Yes --> CheckPort{ntohs(tcph->dest) == block_port?}
    CheckPort -- Yes --> LogTCP[LOG_DROP_RATELIMITED: TCP Port Drop]
    LogTCP --> VerdictDrop
    CheckPort -- No --> VerdictAccept
    
    CheckTCP -- No --> VerdictAccept
```

---

## Repository Architecture

```text
netshield-lkm/
├── Makefile                      # Kbuild build automation (all, clean, load, unload, test, status)
├── LICENSE                       # GNU General Public License v2
├── README.md                     # Comprehensive project documentation and usage guide
├── src/
│   ├── netshield.h               # Macro definitions, logging helpers, fail-safes, constants
│   └── netshield.c               # Core LKM implementation: Netfilter hook callback & lifecycle
├── scripts/
│   ├── load_module.sh            # Helper script for insmod with validation & sysfs checks
│   └── test_traffic.sh           # Comprehensive 7-stage automated bash test harness
└── docs/
    └── Project2_ NetShield-LKM_ A Lightweight In-Kernel Network Packet Filter Using Linux Netfilter Hooks.pdf # Complete technical report
```

---

## Module Parameters

NetShield-LKM exposes its parameters through the Linux `sysfs` virtual filesystem under `/sys/module/netshield/parameters/`:

| Parameter | Type | Default | Access Mode | Description |
| :--- | :--- | :--- | :--- | :--- |
| `block_port` | `ushort` | `0` (disabled) | `0644` (R/W) | Destination TCP port to filter and drop. |
| `drop_icmp` | `bool` | `true` | `0644` (R/W) | Toggle dropping incoming ICMP echo requests (ping). |
| `blacklist_ip` | `charp` | `""` (none) | `0644` (R/W) | Source IPv4 address string to filter and drop (e.g., `"10.0.0.99"`). |
| `allow_loopback_filter` | `bool` | `false` | `0644` (R/W) | Enable filtering on loopback interface `lo` for local testing. |

---

## Build & Quick Start

### 1. Prerequisites
Compiling the kernel module requires the Linux kernel development headers corresponding to your active kernel version:

```bash
# Debian / Kali Linux / Ubuntu
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) python3-docx
```

### 2. Compilation
Compile the module using standard Linux Kbuild:

```bash
make
```

To clean all build artifacts and temporary object files:
```bash
make clean
```

### 3. Loading the Module
You can load the module with default parameters using `make load` or specify custom parameters via `scripts/load_module.sh`:

```bash
# Default parameters (drops ICMP echo requests; port blocking disabled)
sudo make load

# Or with custom rules via scripts/load_module.sh:
sudo ./scripts/load_module.sh --port 8080 --icmp 1 --ip "192.168.1.50"

# Enable loopback filtering for local testing:
sudo ./scripts/load_module.sh --port 8080 --loopback 1
```

### 4. Dynamic Sysfs Reconfiguration
Parameters can be updated on-the-fly at runtime without reloading the module:

```bash
# Inspect current module state and active parameters:
make status

# Dynamically block TCP port 9090:
echo 9090 | sudo tee /sys/module/netshield/parameters/block_port

# Re-enable ping replies:
echo 0 | sudo tee /sys/module/netshield/parameters/drop_icmp
```

### 5. Automated Test Suite
Execute the comprehensive 7-stage automated test suite:

```bash
sudo make test
# or directly:
sudo ./scripts/test_traffic.sh
```

### 6. Unloading the Module
Safely unregister the Netfilter hook and remove the module from kernel memory:

```bash
sudo make unload
```

---

## Empirical Verification Matrix

| Test ID | Test Scenario | Traffic Injection | Expected Subsystem Verdict | Empirical Result |
| :--- | :--- | :--- | :--- | :--- |
| **TEST-1** | Module Loading & Sysfs Verification | `insmod netshield.ko block_port=9090 drop_icmp=1 blacklist_ip="10.0.0.99"` | Module linked in `lsmod`; sysfs parameters match inputs (`Y`, `9090`). | **PASS** |
| **TEST-2** | ICMP Echo Request Drop | `ping -c 2 -W 1 127.0.0.1` with `drop_icmp=1` | Packets dropped at hook; 100% packet loss reported by ping. | **PASS** |
| **TEST-3** | ICMP Echo Request Accept | `ping -c 2 -W 1 127.0.0.1` with `drop_icmp=0` | Packets forwarded unimpeded; 0% packet loss. | **PASS** |
| **TEST-4** | TCP Target Port Drop | TCP SYN to `127.0.0.1:8888` with `block_port=8888` | SYN dropped; client connection times out / fails. | **PASS** |
| **TEST-5** | TCP Allowed Port Forwarding | TCP SYN to `127.0.0.1:8889` with `block_port=8888` | Packet forwarded unimpeded; three-way handshake succeeds. | **PASS** |
| **TEST-6** | Hardcoded SSH Anti-Lockout | TCP SYN to `127.0.0.1:22` with `block_port=22` | Port 22 bypasses drop logic; connection accepted. | **PASS** |
| **TEST-7** | Kernel Log Audit & Formatting | Audit `dmesg` output for drop events | Messages conform to `[NetShield-LKM]` prefix and `%pI4` format. | **PASS** |

---

## Technical Documentation

For complete operating system theory, dual-mode protection mechanics (Ring 0, Ring 3), SoftIRQ atomic context constraints, empirical verification evidence and performance benchmarking, refer to the comprehensive academic technical report:

📄 **[Project2_ NetShield-LKM_ A Lightweight In-Kernel Network Packet Filter Using Linux Netfilter Hooks.pdf](docs/Project2_%20NetShield-LKM_%20A%20Lightweight%20In-Kernel%20Network%20Packet%20Filter%20Using%20Linux%20Netfilter%20Hooks.pdf)**

---

## Troubleshooting & FAQ

### Q1: Why does `nc -z -v 127.0.0.1 22` show `Connection refused` when testing SSH Anti-Lockout?
**Answer:** In TCP/IP networking, `Connection refused` (a TCP RST packet) indicates that **Netfilter ACCEPTED the packet** and delivered it to the local TCP/IP stack, but no user-space SSH server (`sshd`) was actively listening on port 22. If NetShield had dropped the packet, the connection would have hung and timed out (`Connection timed out`). To make the connection succeed, start the SSH service: `sudo systemctl start ssh`.

### Q2: Why is `allow_loopback_filter` disabled by default?
**Answer:** On Linux hosts, local Inter-Process Communication (IPC)—such as systemd-resolved, container runtimes, and local databases—communicates over the loopback interface (`lo` / `127.0.0.1`). Disabling loopback filtering by default prevents accidental self-lockout. For local automated testing on a single machine, pass `allow_loopback_filter=1`.

### Q3: Error: `Kernel headers directory not found at /lib/modules/.../build`
**Answer:** Ensure the development headers matching your active kernel release are installed:
```bash
sudo apt update && sudo apt install -y linux-headers-$(uname -r)
```

---

## Author & License

- **Course:** CPE 333 Operating Systems, King Mongkut's University of Technology Thonburi (KMUTT)
- **Author:** shishiron (Department of Computer Engineering, KMUTT)
- **License:** GNU General Public License v2 (GPL-2.0). See [LICENSE](LICENSE) for full legal text.