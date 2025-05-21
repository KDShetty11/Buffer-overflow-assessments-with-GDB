
# Vulnerability Assessment Report

## Overview

This repository contains the comprehensive security assessment reports conducted for two challenge binaries as part of the CS 647: Counter Hacking Techniques course (Fall 2024):

- **Sam Assessment:** Analysis and exploitation of `/home/sam/helloVuln5`
- **Merry Assessment:** Analysis and exploitation of `/home/merry/retAddr3`

Our objective was to perform vulnerability analysis, exploit buffer overflows, and retrieve protected flag files. This README amalgamates findings, methodologies, and recommendations from both reports.

---

## Team Members

- Kurudunje Deekshith Shetty (ks2378)
- Sri Lasya Varma Indukuri (si289)
- Bhuvaneswar Raju Pericharla (bp534)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Objectives](#objectives)
3. [Methodology \& Steps](#methodology--steps)
4. [Findings \& Exploits](#findings--exploits)
5. [Tools \& Commands](#tools--commands)
6. [Flags Obtained](#flags-obtained)
7. [Mitigations \& Recommendations](#mitigations--recommendations)
8. [References](#references)

---

## Executive Summary

Across both assessments, we identified and exploited buffer overflow vulnerabilities in target programs. By leveraging debugging tools and systematic stack analysis, we were able to:

- **Sam Assessment:** Exploit a buffer overflow in `helloVuln5` to execute arbitrary code and retrieve `samflag.txt`.
- **Merry Assessment:** Overwrite the return address in `retAddr3` to invoke the otherwise inaccessible `getFlag` function, thereby accessing `merryflag.txt`.

Both cases underscore the critical importance of secure coding, input validation, and modern memory protection mechanisms.

---

## Objectives

### Sam Assessment

- Analyze `/home/sam/helloVuln5` for vulnerabilities.
- Gain unauthorized access to `samflag.txt`.


### Merry Assessment

- Analyze `/home/merry/retAddr3` for vulnerabilities.
- Engineer an exploit to invoke `getFlag` and retrieve `merryflag.txt`.

---

## Methodology \& Steps

### Common Approach

1. **Initial Reconnaissance**
    - Enumerate files and permissions.
    - Identify binary type (32-bit, executable).
2. **Disable Security Protections**
    - Disable ASLR (`toggleASLR`) to make memory addresses predictable.
3. **Static and Dynamic Analysis**
    - Use GDB to disassemble and analyze control flow.
    - Identify vulnerable functions (e.g., `strcpy`, `gets`).
4. **Breakpoint Placement**
    - Set breakpoints at vulnerable function calls and after data copying.
5. **Stack Inspection**
    - Examine stack memory to determine buffer sizes and return addresses.
6. **Payload Construction**
    - Calculate required padding to overwrite return addresses.
    - Construct payloads to hijack control flow (either to shellcode or a target function).
7. **Exploit Execution**
    - Run the payload to achieve the objective (read flag files).

---

### Sam Assessment: Step-by-Step

1. **File Discovery**
    - Used `ls` and `file` to identify `helloVuln5` as a 32-bit executable.
2. **Disable ASLR**
    - Ran `toggleASLR`.
3. **Debugging with GDB**
    - Set breakpoints at `main` and `vulnFunction`.
    - Disassembled functions to understand flow and locate `strcpy` vulnerability.
4. **Stack Analysis**
    - Used `x/1000xw $esp` to examine memory.
    - Located buffer start and return address.
    - Calculated padding required to overwrite EIP (574 bytes).
5. **Payload Crafting**
    - Used NOP sleds and shellcode, followed by the return address pointing to the NOP region.
    - Payload example:

```bash
./helloVuln5 $(perl -e 'print "\x90"x500')$(cat shell.bin)$(perl -e 'print "\x90"x51 . "\x10\xcd\xff\xff"')
```

6. **Exploit Success**
    - Retrieved contents of `samflag.txt`.

---

### Merry Assessment: Step-by-Step

1. **File Discovery**
    - Identified `retAddr3` and inaccessible `merryflag.txt`.
2. **Disable ASLR**
    - Used `toggleASLR`.
3. **Debugging with GDB**
    - Disassembled `main`, found `vuln` and `getFlag` functions.
    - Identified usage of unsafe `gets()` function.
4. **Stack Analysis**
    - Set breakpoints, ran test inputs, and examined stack with `x/500xw $esp`.
    - Calculated required offset (615 bytes) to reach return address.
5. **Payload Crafting**
    - Overwrote return address to point to `getFlag`.
    - Payload example:

```bash
./retAddr3 $(perl -e 'print "A"x615 . "\xc2\x63\x55\x56"')
```

6. **Exploit Success**
    - Accessed and displayed contents of `merryflag.txt`.

---

## Findings \& Exploits

| Assessment | Vulnerability | Exploit Method | Outcome |
| :-- | :-- | :-- | :-- |
| Sam | Buffer Overflow | Overwrite EIP, inject shellcode | Read `samflag.txt` |
| Merry | Buffer Overflow | Overwrite return address | Invoked `getFlag`, read flag file |

**Key Lessons:**

- Unsafe string functions (`strcpy`, `gets`) are highly exploitable.
- Lack of modern protections (ASLR, DEP) facilitates exploitation.
- Precise stack analysis is critical for successful exploitation.

---

## Tools \& Commands

| Tool/Command | Purpose/Usage |
| :-- | :-- |
| `file` | Identify binary type |
| `ls -l` | Enumerate files and permissions |
| `cat` | Display file contents |
| `perl -e` | Generate payloads (repeated characters, shellcode) |
| `gdb` | Debugging, disassembly, stack inspection |
| `break` | Set breakpoints in GDB |
| `disassemble` | View assembly code |
| `x/1000xw $esp` | Examine memory |
| `toggleASLR` | Enable/disable ASLR |

**Example Payload Construction:**

```bash
# For helloVuln5
./helloVuln5 $(perl -e 'print "\x90"x500')$(cat shell.bin)$(perl -e 'print "\x90"x51 . "\x10\xcd\xff\xff"')

# For retAddr3
./retAddr3 $(perl -e 'print "A"x615 . "\xc2\x63\x55\x56"')
```


---

## Flags Obtained

### Sam Assessment

- **Kurudunje Deekshith Shetty:**
`58ba28073502498c531f1c53e3797604c209d9813692dc61d685a766797c6d33...`
- **Sri Lasya Varma Indukuri:**
`1974b08e03d35267a66ca44dacc86d7ab582e4c1a34ebf8d19bdd9e259f2978f...`
- **Bhuvaneswar Raju Pericharla:**
`dde660200353d4235cdcf5eb133260698013b313cae66ee4ce2b7bd79d2ac3a0...`


### Merry Assessment

- (Flag contents retrieved from `merryflag.txt` as proof of successful exploitation.)

---

## Mitigations \& Recommendations

To prevent similar vulnerabilities:

- **Use Safe String Functions:** Replace `strcpy`, `gets` with bounded alternatives like `strncpy`, `fgets`.
- **Input Validation:** Always validate user input length.
- **Enable Security Features:**
    - Address Space Layout Randomization (ASLR)
    - Data Execution Prevention (DEP)
    - Stack canaries
- **Regular Security Audits:** Perform code reviews and penetration testing.
- **Education:** Train developers on secure coding practices.

---

## References

- Course lecture videos and slides, special thanks to professor Michael Martin.
- GDB documentation.
- Linux man pages for debugging and system commands.

---

**End of README**

<div style="text-align: center">⁂</div>

[^1]: Sam-Assessment-Report-Team-4.pdf

[^2]: Merry-Assessment-Report-Team-4.pdf

[^3]: Legolas-Assessment-Report.pdf


