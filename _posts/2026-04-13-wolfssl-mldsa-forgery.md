---
layout: post
title: "\"Shall Destroy, Did Not\": Recovering ML-DSA Private Keys from wolfSSL's Heap"
date: 2026-04-13 00:00:00 +0000
categories: [Security, Advisory]
tags: [wolfssl, ml-dsa, dilithium, fips-204, pqc, signature-forgery, cwe-226]
description: "wolfSSL's ML-DSA signing implementation does not destroy private key material after use, violating FIPS 204 Section 3.6.3. The unzeroed heap block is recoverable via same-process allocation, enabling end-to-end signature forgery."
toc: true
pin: true
---

## Summary

wolfSSL's ML-DSA signing implementation frees a ~50KB heap block containing private signing material (s1, s2, t0 in NTT form) without clearing it, in violation of the FIPS 204 Section 3.6.3 mandatory destruction requirement. For a same-process attacker able to allocate and read a same-size heap block, this material is recoverable -- demonstrated on glibc tcache across three Linux distributions and macOS. Recovery of s1 is sufficient for full signing key compromise and arbitrary signature forgery, verified end-to-end against the compiled `libwolfssl` binary.

wolfSSL confirmed the finding, patched it ([#10100](https://github.com/wolfSSL/wolfssl/pull/10100), [#10113](https://github.com/wolfSSL/wolfssl/pull/10113)), and credited the reporter. After evaluating the heap-reuse PoC, wolfSSL acknowledged it is "correct in using the data obtained from the heap buffer" but declined to assign a CVE.

> **Affected:** wolfSSL v5.7.2 -- v5.9.0-stable, native `WOLFSSL_WC_DILITHIUM` builds (requires `--enable-mldsa` or `--enable-dilithium`, not included in `--enable-all`). **Fix:** [v5.9.1](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.1-stable) (released April 8, 2026) includes PRs [#10100](https://github.com/wolfSSL/wolfssl/pull/10100) and [#10113](https://github.com/wolfSSL/wolfssl/pull/10113). Update to v5.9.1 or later.

---

## Threat Model

The attacker is code running in the same process as the ML-DSA signing operation -- a plugin, a callback handler, a co-loaded library, a scripting engine, or any component in a multi-tenant service that shares the process address space with the signer. The attacker can call `malloc` and read the returned buffer. This is the standard threat model for cryptographic zeroization requirements: it is the reason `ForceZero`, `OPENSSL_cleanse`, `explicit_bzero`, and `SecureZeroMemory` exist.

The attacker does NOT need: a memory-corruption vulnerability, a core dump, `/proc/pid/mem` access, or any privilege beyond normal same-process execution.

---

## The Bug

wolfSSL already fixed this exact zeroization pattern in dilithium keygen ([643427040](https://github.com/wolfSSL/wolfssl/commit/643427040)), ed25519 signing ([5f7bc0f3a](https://github.com/wolfSSL/wolfssl/commit/5f7bc0f3a)), and ed448 signing ([109e765b5](https://github.com/wolfSSL/wolfssl/commit/109e765b5)). The ML-DSA signing path was missed.

`dilithium_sign_with_seed_mu()` in `wolfcrypt/src/dilithium.c`, line 8417:

```c
XFREE(y, key->heap, DYNAMIC_TYPE_DILITHIUM);  // no ForceZero
return ret;
```

The freed block is 50,176 bytes for ML-DSA-44 (sizes differ for ML-DSA-65/87 but the same code path applies). With `WC_DILITHIUM_CACHE_PRIV_VECTORS` off (the default), it contains the private key polynomials at fixed offsets:

| Offset | Contents | Note |
|--------|----------|------|
| 21504 | **s1** -- static secret signing key | NTT-small domain |
| 25600 | s2 | NTT domain |
| 29696 | t0 | NTT domain |

*(Offsets shown are for ML-DSA-44 with default build configuration.)*

---

## The Attack

1. Application signs message M1. wolfSSL allocates the ~50 KB block, writes s1/s2/t0 in NTT form, frees it without zeroing.
2. Any code in the same process calls `malloc(50176)`. The chunk is too large for glibc's tcache (~1 KB max) and goes through the unsorted/large-bin path; for a single-threaded process with no intervening same-size allocations, `malloc(50176)` returns the same chunk with its payload bytes intact. Read s1 from offset 21504.
3. Forge a signature on a different message M2 using s1 + the public key.

s1 is the static signing key. One recovery = permanent key compromise for all messages under that key.

The forgery uses hint reconstruction (no s2 or t0 needed). The perturbation bound for ML-DSA-44 (`tau*(2^(d-1) + eta) = 159,822 < 2*gamma2 = 190,464`) guarantees the hints are always correct, so the forged signature passes verification.

---

## PoC

The PoC ([poc_heap_forgery_v2.c](https://github.com/abhinavagarwal07/abhinavagarwal07.github.io/blob/main/assets/poc/wolfssl-mldsa/poc_heap_forgery_v2.c)) includes `wolfcrypt/src/dilithium.c` directly to access static NTT/expand functions needed for the forgery math. A companion verifier ([verify_forged.c](https://github.com/abhinavagarwal07/abhinavagarwal07.github.io/blob/main/assets/poc/wolfssl-mldsa/verify_forged.c)) links against the compiled `libwolfssl` binary -- not an inlined copy -- and independently confirms `wc_dilithium_verify_msg()` accepts the forged signature.

```
$ ./poc_heap_forgery_v2
signed m1 (2420 bytes)

--- heap reuse ---
got 12519/12544 nonzero dwords in block
s1 at offset 21504: 1024/1024 nonzero
baseline sig1 verifies ok

--- wiping private key ---

--- forging sig on m2 ---
  m1: "Hello world - legitimate message"
  m2: "this msg was forged via heap reuse"
  forged on attempt 1 (kf=0)

FORGERY OK - wc_dilithium_verify_msg accepted forged sig on m2

$ ./verify_forged
pk: 1312 bytes, sig: 2420 bytes, msg: 34 bytes
VERIFIED - linked libwolfssl accepted the forged signature
```

**Test results** (wolfSSL v5.9.0-stable, -O2):

| Platform | Arch | Compiler | libc | Result |
|----------|------|----------|------|--------|
| Ubuntu 22.04.5 (Azure B2ls_v2) | x86_64 | gcc 11.4.0 | glibc 2.35 | **10/10** |
| Amazon Linux 2023 | x86_64 | gcc | glibc 2.34 | 5/5 |
| Ubuntu 20.04 | x86_64 | gcc | glibc 2.31 | 5/5 |

Heap reclamation is **allocator-dependent**. macOS's magazine allocator (libmalloc) does not reliably return the same chunk on sequential free -> malloc of the same size; on the systems tested the heap-reuse PoC observed 0/100 reclaim. The underlying zeroization bug is still present -- the freed block retains s1 in memory regardless -- but practical recovery on macOS would need a different primitive (e.g. `/proc`-like memory inspection or a core dump) rather than in-process malloc reuse. musl and jemalloc were not tested.

Build instructions are in the PoC file headers.

### Limitations

- The PoC targets ML-DSA-44 with default build flags. The heap block size and s1 offset differ for ML-DSA-65/87, but the underlying missing-ForceZero bug is the same.
- Heap reuse depends on glibc's unsorted/large-bin path (the 50,176-byte chunk exceeds tcache's ~1 KB maximum, so it does not enter tcache). Subsequent allocator activity can partially overwrite the front of the freed chunk via the unsorted-bin splitter, but s1 at offset 21504 is past the typical split boundary. Custom `XMALLOC` hooks, non-glibc allocators (musl, jemalloc), or heavy multithreaded intervening allocations may not preserve the residue.
- The forgery includes `dilithium.c` directly for access to static NTT functions. The companion `verify_forged.c` confirms the result against the real library binary.

---

## FIPS 204 Non-Conformance

> "implementations of ML-DSA **shall** ensure that any potentially sensitive intermediate data is destroyed as soon as it is no longer needed."
>
> -- FIPS 204, Section 3.6.3

"shall" is normative under NIST conventions -- it means mandatory. The unzeroed heap block containing s1, s2, and t0 directly violates this requirement.

wolfSSL's active FIPS 140-3 certificate [#4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718) (wolfCrypt v5.2.1) does not include ML-DSA in its validated boundary. However, wolfSSL has a [pending FIPS 140-3 submission](https://www.wolfssl.com/coming-soon-wolfssl-takes-pqc-toward-fips-certification/) with ML-DSA in scope. The §3.6.3 violation is relevant to that submission.

---

## Vendor Response

wolfSSL confirmed, patched, and credited the finding. Their response was fast and professional -- patches landed within two days of the initial report.

wolfSSL classified the finding as a bug rather than a vulnerability, noting that exploitation requires "some other vulnerability to actually trigger the extraction of the sensitive data from the heap buffer." After evaluating the heap-reuse PoC, they acknowledged it is "correct in using the data obtained from the heap buffer" but maintained their position.

wolfSSL already fixed this exact pattern -- missing `ForceZero` before free of private key material -- in dilithium keygen, ed25519 signing, and ed448 signing. The ML-DSA signing path was missed.

A follow-up proof-of-concept (see *Follow-Up* section below) demonstrates the same bug is exploitable from a different process on the same host via `/proc/$pid/mem`, and from an off-process attacker via crash-reporter core ingest -- without requiring any second memory-disclosure bug in wolfSSL itself.

No CVE has been assigned.

---

## Mitigations

If you use wolfSSL with `--enable-mldsa` and cannot update immediately:
- **Isolate signing into a separate process under a separate UID, with core dumps disabled and no shared crash-reporter pipeline.** Same-process isolation is necessary but not sufficient. Cross-process `/proc/$pid/mem` access depends on the kernel's `yama/ptrace_scope`:
  - `ptrace_scope=0` (CentOS/RHEL default) -- any same-UID attacker can read.
  - `ptrace_scope=1` (Ubuntu/Debian default) -- attacker must be a parent/ancestor of the signer, or hold `CAP_SYS_PTRACE`.
  - `ptrace_scope=2` -- attacker must hold `CAP_SYS_PTRACE`.
  Any crash collector that captures the signer's core may contain the residue even without a live process. See the *Follow-Up* section below.
- **Use a zero-on-free allocator.** Custom `XMALLOC`/`XFREE` hooks that zero memory before returning it to the allocator prevent stale data recovery.
- **Enable `WC_DILITHIUM_CACHE_PRIV_VECTORS` (partial mitigation).** With caching on, s1/s2/t0 are held in the key struct across signing calls rather than being recomputed into the per-signing scratch each time -- reducing but not eliminating the scratch-block residue surface. The full private key is still resident in the key struct itself and must be zeroized there; this flag is not a substitute for the v5.9.1 patch.

---

## Follow-Up (2026-04-17): Attacks Beyond Same-Process

Two follow-up PoCs demonstrate the same heap-residue bug is exploitable without an attacker executing code inside the signer process. Both produce forgeries verified end-to-end against the installed `libwolfssl.so.44.1.0` binary on Ubuntu 22.04 x86_64, wolfSSL v5.9.0-stable compiled with `-O2 -g --enable-dilithium`.

### S1 -- Off-process via crash collector

A signer that crashes for an unrelated reason after signing emits a core dump. `systemd-coredump` (the Linux default) or an integrated crash reporter (Crashpad, Sentry Native, Google Breakpad, Windows Error Reporting) captures the core. An attacker with access only to the core file extracts s1 and forges. End-to-end time from core file to verified forgery: under 0.4 seconds. The signer never allocates a second 50,176-byte block -- the alloc/free sequence is entirely inside the victim; the attacker never executes code in the signer process.

*Caveat for honesty:* the core dump also contains the live `dilithium_key` struct, so against a typical signer the struct-side leak is the easier path. The scratch-block residue matters for signers that wipe the key struct but forget the per-signing scratch -- including hardened wrappers, HSM-adjacent helpers that hold the key only transiently, and any deployment that relies on wolfSSL's own `ForceZero` on the key struct (which is implemented) while assuming the scratch block is not sensitive (which it is). The FIPS 204 §3.6.3 "shall destroy" requirement applies to the scratch block regardless of what else lives in memory.

### S4 -- Cross-process via `/proc/$pid/mem`

A different process on the same host reads `/proc/<victim_pid>/mem`. On Ubuntu 22.04 with default `kernel.yama.ptrace_scope=1`, the *parent-topology* case succeeds: a long-lived daemon that spawns the signer as a child (matching the GitHub Actions runner-agent / signing-job relationship, and many systemd-supervised service patterns) reads the child's memory without any extra privilege. The sibling-topology case works on distributions that ship `ptrace_scope=0` (CentOS/RHEL family) or with `CAP_SYS_PTRACE`. Extraction still succeeds **300 seconds post-sign** in empirical testing, so the attacker is not time-pressured.

### Extraction fingerprint

Both follow-up PoCs locate the dilithium scratch block by looking for its **public** matrix `A` at offset +33,792: 16,384 bytes (4,096 signed 32-bit words) all in `[0, Q)` where `Q = 8,380,417`. For random bytes the probability of matching is `(Q/2^32)^4096`, i.e. effectively zero -- the A-matrix check is a near-perfect signature. Once the block start is anchored, s1 is read at +21,504; as a corroborating check each 4,096-byte s1 candidate is 32-bit-word-bounded by `(-4Q, 4Q)` (NTT-small Montgomery domain is only loosely reduced, so values span roughly that range rather than the tight `[-eta, eta]` that applies in the standard domain). A cryptographic forge test is applied to each surviving candidate as a final discriminator: the real s1 produces a signature that `wc_dilithium_verify_msg()` accepts, any other window does not.

PoC source for the follow-up is held pending CVE coordination with CISA as the Root-CNA for wolfSSL.

---

## Downstream

Potential downstream impact wherever wolfSSL's native ML-DSA signing path is used. Publicly documented examples include [wolfBoot](https://www.wolfssl.com/products/wolfBoot/) (firmware signing) and [wolfCLU](https://github.com/wolfSSL/wolfCLU) (command-line signing utility).

---

## Timeline

| Date | Event |
|------|-------|
| 2026-03-28 | Report sent to wolfSSL with forgery PoC |
| 2026-03-30 | wolfSSL confirmed. PR [#10100](https://github.com/wolfSSL/wolfssl/pull/10100). |
| 2026-03-30 | Heap block addendum + patch sent |
| 2026-03-31 | PR [#10113](https://github.com/wolfSSL/wolfssl/pull/10113). Declined CVE. |
| 2026-04-02 | wolfSSL reaffirmed: "bugs, not vulnerabilities." Closed. |
| 2026-04-09 | Heap-reuse PoC sent to wolfSSL |
| 2026-04-10 | wolfSSL evaluated PoC, acknowledged correctness, maintained classification |
| 2026-04-13 | Public disclosure |
| 2026-04-17 | Follow-up PoCs added: core-dump extraction and cross-process `/proc/mem` extraction |

No CVE assigned.

---

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) -- Section 3.6.3
- [wolfSSL PR #10100](https://github.com/wolfSSL/wolfssl/pull/10100) -- stack + seedMu fix
- [wolfSSL PR #10113](https://github.com/wolfSSL/wolfssl/pull/10113) -- heap block + seed fix
- [CWE-226](https://cwe.mitre.org/data/definitions/226.html) -- Sensitive Information in Resource Not Removed Before Reuse
- [CWE-244](https://cwe.mitre.org/data/definitions/244.html) -- Improper Clearing of Heap Memory Before Release
