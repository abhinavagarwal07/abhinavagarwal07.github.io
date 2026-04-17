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

wolfSSL's ML-DSA signing implementation frees a ~50 KB heap block containing private signing material (s1, s2, t0 in NTT form) without clearing it, violating FIPS 204 Section 3.6.3. For a same-process attacker able to allocate and read a same-size heap block, this material is recoverable -- demonstrated on glibc across three Linux distributions. Recovery of s1 is sufficient for full signing-key compromise and arbitrary signature forgery, verified end-to-end against the compiled `libwolfssl` binary.

wolfSSL confirmed the finding, patched it ([#10100](https://github.com/wolfSSL/wolfssl/pull/10100), [#10113](https://github.com/wolfSSL/wolfssl/pull/10113)), and credited the reporter. It declined to assign a CVE.

> **Affected:** wolfSSL v5.7.2 -- v5.9.0-stable, native `WOLFSSL_WC_DILITHIUM` builds (requires `--enable-mldsa` or `--enable-dilithium`; not included in `--enable-all`). **Fix:** [v5.9.1](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.1-stable) (April 8, 2026). Update to v5.9.1 or later.

Off-process recovery primitives (core-dump ingest, cross-process `/proc/$pid/mem`) are covered in a [follow-up post]({% post_url 2026-04-17-wolfssl-mldsa-offprocess %}).

---

## How It Works

The attacker is code running in the same process as the ML-DSA signing operation -- a plugin, callback handler, co-loaded library, scripting engine, or any component that shares the process address space. The attacker can call `malloc` and read the returned buffer. This is the standard threat model the existence of `ForceZero`, `OPENSSL_cleanse`, `explicit_bzero`, and `SecureZeroMemory` is premised on.

The attacker does **not** need a memory-corruption vulnerability, a core dump, `/proc/pid/mem` access, or any privilege beyond normal same-process execution.

### The missed `ForceZero`

`dilithium_sign_with_seed_mu()` in `wolfcrypt/src/dilithium.c`, line 8417:

```c
XFREE(y, key->heap, DYNAMIC_TYPE_DILITHIUM);  // no ForceZero
return ret;
```

wolfSSL already fixed this exact pattern in dilithium keygen ([643427040](https://github.com/wolfSSL/wolfssl/commit/643427040)), ed25519 signing ([5f7bc0f3a](https://github.com/wolfSSL/wolfssl/commit/5f7bc0f3a)), and ed448 signing ([109e765b5](https://github.com/wolfSSL/wolfssl/commit/109e765b5)). The ML-DSA signing path was missed.

The freed block is 50,176 bytes for ML-DSA-44. With `WC_DILITHIUM_CACHE_PRIV_VECTORS` off (the default) it contains the private-key polynomials at fixed offsets:

| Offset | Contents | Note |
|--------|----------|------|
| 21504 | **s1** -- static secret signing key | NTT-small domain |
| 25600 | s2 | NTT domain |
| 29696 | t0 | NTT domain |

*(Offsets are for ML-DSA-44 with default build configuration. ML-DSA-65/87 use a different block size but the same bug.)*

### Exploit chain

1. Application signs message M1. wolfSSL allocates the ~50 KB block, writes s1/s2/t0 in NTT form, frees it without zeroing.
2. Any code in the same process calls `malloc(50176)`. The chunk is too large for glibc's tcache (~1 KB max) and goes through the unsorted/large-bin path; for a single-threaded process with no intervening same-size allocations, `malloc(50176)` returns the same chunk with its payload intact. Read s1 from offset 21504.
3. Forge a signature on a different message M2 using s1 plus the public key.

s1 is the static signing key. One recovery = permanent key compromise for every message under that key.

<details markdown="1">
<summary>Why the forged signature verifies (perturbation-bound detail)</summary>

The forgery uses hint reconstruction; s2 and t0 are not needed. For ML-DSA-44, `tau*(2^(d-1) + eta) = 159,822 < 2*gamma2 = 190,464`, which guarantees the reconstructed hints are always correct and the forged signature passes `wc_dilithium_verify_msg()`.
</details>

---

## PoC

The PoC ([poc_heap_forgery_v2.c](https://github.com/abhinavagarwal07/abhinavagarwal07.github.io/blob/main/assets/poc/wolfssl-mldsa/poc_heap_forgery_v2.c)) links `wolfcrypt/src/dilithium.c` directly for access to static NTT/expand functions. A companion verifier ([verify_forged.c](https://github.com/abhinavagarwal07/abhinavagarwal07.github.io/blob/main/assets/poc/wolfssl-mldsa/verify_forged.c)) links against the compiled `libwolfssl` binary -- not an inlined copy -- and independently confirms `wc_dilithium_verify_msg()` accepts the forged signature:

```
$ ./poc_heap_forgery_v2
...
FORGERY OK - wc_dilithium_verify_msg accepted forged sig on m2

$ ./verify_forged
VERIFIED - linked libwolfssl accepted the forged signature
```

**Test results** (wolfSSL v5.9.0-stable, `-O2`):

| Platform | Arch | libc | Result |
|----------|------|------|--------|
| Ubuntu 22.04.5 (Azure B2ls_v2) | x86_64 | glibc 2.35 | **10/10** |
| Amazon Linux 2023 | x86_64 | glibc 2.34 | 5/5 |
| Ubuntu 20.04 | x86_64 | glibc 2.31 | 5/5 |

Heap reclamation is allocator-dependent. macOS libmalloc did not return the same chunk on sequential free -> malloc (0/100); the freed block still contains s1 but recovery needs a different primitive (e.g. `/proc`, core dump). musl and jemalloc were not tested.

Build instructions are in the PoC file headers.

---

## Why It Matters

### FIPS 204 non-conformance

> "implementations of ML-DSA **shall** ensure that any potentially sensitive intermediate data is destroyed as soon as it is no longer needed."
>
> -- FIPS 204, Section 3.6.3

"shall" is normative under NIST conventions. The unzeroed heap block containing s1, s2, and t0 directly violates this requirement. wolfSSL's active FIPS 140-3 certificate [#4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718) (wolfCrypt v5.2.1) does not include ML-DSA in its validated boundary, but wolfSSL has a [pending FIPS 140-3 submission](https://www.wolfssl.com/coming-soon-wolfssl-takes-pqc-toward-fips-certification/) with ML-DSA in scope. The §3.6.3 violation is relevant to that submission.

### Vendor response

wolfSSL confirmed, patched, and credited the finding within two days of the initial report. It classified the finding as a bug rather than a vulnerability, noting that exploitation requires "some other vulnerability to actually trigger the extraction of the sensitive data from the heap buffer." After evaluating the heap-reuse PoC, wolfSSL acknowledged it is "correct in using the data obtained from the heap buffer" but maintained the classification. No CVE has been assigned.

A [follow-up post]({% post_url 2026-04-17-wolfssl-mldsa-offprocess %}) shows the same bug is exploitable from a different process on the same host via `/proc/$pid/mem`, and from an off-process attacker via crash-reporter core ingest -- without requiring any second memory-disclosure bug in wolfSSL itself.

---

## Mitigations

If you use wolfSSL with `--enable-mldsa` and cannot update to v5.9.1 immediately:

- **Isolate signing into a separate process under a separate UID, with core dumps disabled and no shared crash-reporter pipeline.** Same-process isolation is necessary but not sufficient -- see the [follow-up post]({% post_url 2026-04-17-wolfssl-mldsa-offprocess %}) for cross-process and off-process recovery.
- **Use a zero-on-free allocator.** Custom `XMALLOC`/`XFREE` hooks that zero memory before returning it to the allocator prevent stale-data recovery.
- **Enable `WC_DILITHIUM_CACHE_PRIV_VECTORS` (partial mitigation).** With caching on, s1/s2/t0 are held in the key struct across signing calls rather than recomputed into the scratch each time -- reducing but not eliminating the scratch-block residue surface. The full private key is still resident in the key struct itself and must be zeroized there; this flag is not a substitute for the v5.9.1 patch.

---

## Downstream

Potential downstream impact wherever wolfSSL's native ML-DSA signing path is used. Publicly documented examples include [wolfBoot](https://www.wolfssl.com/products/wolfBoot/) (firmware signing) and [wolfCLU](https://github.com/wolfSSL/wolfCLU) (command-line signing utility).

---

## Timeline

| Date | Event |
|------|-------|
| 2026-03-28 | Report sent to wolfSSL with forgery PoC |
| 2026-03-30 | wolfSSL confirmed. PR [#10100](https://github.com/wolfSSL/wolfssl/pull/10100). Heap block addendum + patch sent. |
| 2026-03-31 | PR [#10113](https://github.com/wolfSSL/wolfssl/pull/10113). Declined CVE. |
| 2026-04-02 | wolfSSL reaffirmed: "bugs, not vulnerabilities." Closed. |
| 2026-04-09 | Heap-reuse PoC sent to wolfSSL |
| 2026-04-10 | wolfSSL evaluated PoC, acknowledged correctness, maintained classification |
| 2026-04-13 | Public disclosure |
| 2026-04-17 | [Follow-up post]({% post_url 2026-04-17-wolfssl-mldsa-offprocess %}): core-dump extraction and cross-process `/proc/mem` extraction |

---

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) -- Section 3.6.3
- [wolfSSL PR #10100](https://github.com/wolfSSL/wolfssl/pull/10100) -- stack + seedMu fix
- [wolfSSL PR #10113](https://github.com/wolfSSL/wolfssl/pull/10113) -- heap block + seed fix
- [CWE-226](https://cwe.mitre.org/data/definitions/226.html) -- Sensitive Information in Resource Not Removed Before Reuse
- [CWE-244](https://cwe.mitre.org/data/definitions/244.html) -- Improper Clearing of Heap Memory Before Release
