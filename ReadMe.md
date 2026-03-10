# Advanced Binary Exploitation Research

## Overview

Security research project demonstrating buffer overflow exploitation techniques on 32-bit ELF binaries. Two vulnerable programs were analyzed and exploited using GDB, stack analysis, and payload crafting to achieve arbitrary code execution and control flow hijacking.

---

## Objectives

- Analyze 32-bit ELF binaries for memory corruption vulnerabilities
- Develop working exploits using stack-based buffer overflow techniques
- Demonstrate return address overwrite and shellcode injection attacks
- Document mitigations and secure coding recommendations

---

## Methodology

### General Approach

1. **Reconnaissance** -- Identify binary type, permissions, and linked libraries
2. **Static/Dynamic Analysis** -- Disassemble with GDB, identify unsafe functions (`strcpy`, `gets`)
3. **Stack Inspection** -- Map buffer layout, locate return addresses, calculate offsets
4. **Payload Construction** -- Build NOP sleds, shellcode payloads, and return address overwrites
5. **Exploitation** -- Execute payloads to hijack control flow

---

### Assessment 1: Shellcode Injection

- **Target:** 32-bit executable using `strcpy` (no bounds checking)
- **Technique:** Classic stack-based buffer overflow with NOP sled + shellcode
- **Stack offset:** 574 bytes to overwrite EIP
- **Payload:**
  ```bash
  ./target $(perl -e 'print "\x90"x500')$(cat shell.bin)$(perl -e 'print "\x90"x51 . "\x10\xcd\xff\xff"')
  ```
- **Result:** Achieved arbitrary code execution, read protected file

### Assessment 2: Return-to-Function

- **Target:** 32-bit executable using `gets()` with an unreachable function
- **Technique:** Overwrite return address to redirect execution to target function
- **Stack offset:** 615 bytes to reach saved return address
- **Payload:**
  ```bash
  ./target $(perl -e 'print "A"x615 . "\xc2\x63\x55\x56"')
  ```
- **Result:** Successfully invoked hidden function, read protected file

---

## Findings

| Assessment | Vulnerability | Exploit Method | Outcome |
| :-- | :-- | :-- | :-- |
| 1 | Buffer Overflow (`strcpy`) | NOP sled + shellcode injection | Arbitrary code execution |
| 2 | Buffer Overflow (`gets`) | Return address overwrite | Control flow hijack |

**Key Takeaways:**
- Unsafe C string functions remain a critical vulnerability class
- Without ASLR, DEP, and stack canaries, exploitation is straightforward
- Precise stack layout mapping via GDB is essential for reliable exploits

---

## Tools Used

| Tool | Purpose |
| :-- | :-- |
| GDB | Debugging, disassembly, memory inspection |
| `objdump` | Static binary analysis |
| `file` | Binary identification |
| Perl | Payload generation |
| Python | Exploit scripting |

---

## Mitigations & Recommendations

- **Use safe string functions:** Replace `strcpy`/`gets` with `strncpy`/`fgets`
- **Enable ASLR:** Randomize memory layout to prevent hardcoded addresses
- **Enable DEP/NX:** Mark stack as non-executable to block shellcode
- **Stack canaries:** Detect buffer overflows before return address is used
- **Input validation:** Always validate and bound user input lengths
- **Regular security audits:** Code review and penetration testing

---

## Author

**Kurudunje Deekshith Shetty**
