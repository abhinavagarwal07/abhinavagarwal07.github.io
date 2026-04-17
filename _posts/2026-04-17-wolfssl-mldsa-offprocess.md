---
layout: post
title: "ML-DSA Forgery, Part 2: Off-Process Key Recovery in wolfSSL"
date: 2026-04-17 00:00:00 +0000
categories: [Security, Advisory]
tags: [wolfssl, ml-dsa, dilithium, fips-204, pqc, signature-forgery, cwe-226]
description: "The same wolfSSL ML-DSA heap-zeroization bug is exploitable from off-process: via crash-reporter core ingest, and via cross-process /proc/$pid/mem. Both verified end-to-end against installed libwolfssl."
toc: true
---

## Recap

The [original post]({% post_url 2026-04-13-wolfssl-mldsa-forgery %}) showed that wolfSSL's ML-DSA signing path frees a 50,176-byte heap block containing the private-key polynomials (s1, s2, t0 in NTT form) without calling `ForceZero`. A same-process attacker recovers s1 via `malloc(50176)` and forges. wolfSSL's position: exploitation "requires some other vulnerability to actually trigger the extraction of the sensitive data from the heap buffer."

This post validates two off-process recovery paths. In neither case does the attacker execute code inside the signer process. Both are verified end-to-end against the installed `libwolfssl.so.44.1.0` on Ubuntu 22.04 x86_64, wolfSSL v5.9.0-stable compiled with `-O2 -g --enable-dilithium`.

---

## S1 -- Off-host via crash collector

A signer that crashes for an unrelated reason after signing emits a core dump. `systemd-coredump` (the Linux default) or an integrated crash reporter (Crashpad, Sentry Native, Google Breakpad, Windows Error Reporting) captures the core. An attacker with access only to the core file extracts s1 and forges. End-to-end time from core file to verified forgery: under 0.4 seconds. The signer never allocates a second 50,176-byte block -- the alloc/free sequence is entirely inside the victim; the attacker never executes code in the signer process.

*Honest caveat.* The core dump also contains the live `dilithium_key` struct, so against a typical signer the struct-side leak is the easier path. The scratch-block residue matters for signers that wipe the key struct but forget the per-signing scratch -- including hardened wrappers, HSM-adjacent helpers that hold the key only transiently, and any deployment relying on wolfSSL's own `ForceZero` on the key struct while treating the scratch as non-sensitive. The FIPS 204 §3.6.3 "shall destroy" requirement applies to the scratch block regardless of what else is in memory.

---

## S4 -- Cross-process via `/proc/$pid/mem`

A different process on the same host reads `/proc/<victim_pid>/mem`. On Ubuntu 22.04 with default `kernel.yama.ptrace_scope=1`, the *parent-topology* case succeeds: a long-lived daemon that spawns the signer as a child (matching the GitHub Actions runner-agent / signing-job relationship, and many systemd-supervised service patterns) reads the child's memory without any extra privilege. The sibling-topology case works on distributions that ship `ptrace_scope=0` (CentOS/RHEL family) or with `CAP_SYS_PTRACE`. Extraction still succeeds **300 seconds post-sign** in empirical testing, so the attacker is not time-pressured.

<details markdown="1">
<summary><code>ptrace_scope</code> matrix</summary>

- `ptrace_scope=0` (CentOS/RHEL default) -- any same-UID attacker can read.
- `ptrace_scope=1` (Ubuntu/Debian default) -- attacker must be a parent/ancestor of the signer, or hold `CAP_SYS_PTRACE`.
- `ptrace_scope=2` -- attacker must hold `CAP_SYS_PTRACE`.
</details>

---

## Extraction

Both follow-up PoCs locate the dilithium scratch block by looking for its **public** matrix `A` at offset +33,792: 16,384 bytes (4,096 signed 32-bit words) all in `[0, Q)` where `Q = 8,380,417`. For random bytes the probability of matching is `(Q/2^32)^4096`, i.e. effectively zero -- the A-matrix check is a near-perfect signature. Once the block start is anchored, s1 is read at +21,504.

<details markdown="1">
<summary>Corroborating check and discriminator</summary>

Each 4,096-byte s1 candidate is 32-bit-word-bounded by `(-4Q, 4Q)` -- NTT-small Montgomery domain is only loosely reduced, so values span roughly that range rather than the tight `[-eta, eta]` that applies in the standard domain. A cryptographic forge test is the final discriminator: the real s1 produces a signature that `wc_dilithium_verify_msg()` accepts, any other window does not.
</details>

PoC source for the follow-up is held pending CVE coordination with CISA as the Root-CNA for wolfSSL.

---

## Why this matters for the CVE dispute

wolfSSL's stated reason for declining a CVE is that the bug "requires some other vulnerability to actually trigger the extraction of the sensitive data from the heap buffer." The two PoCs above do not require any second memory-disclosure bug in wolfSSL: S1 uses the operating system's default crash-reporting subsystem; S4 uses the kernel's standard `/proc` interface under a common process-supervision pattern. Both are policies and defaults, not exploits.

The [original disclosure]({% post_url 2026-04-13-wolfssl-mldsa-forgery %}) remains the primary finding; the off-process results broaden the threat model and address the vendor's stated objection.
