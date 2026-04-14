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

1. Application signs message M1. wolfSSL allocates the 50KB block, writes s1/s2/t0 in NTT form, frees it without zeroing.
2. Any code in the same process calls `malloc(50176)`. glibc tcache returns the same block. Read s1 from offset 21504.
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

| Platform | Arch | Compiler | glibc | Result |
|----------|------|----------|-------|--------|
| Ubuntu 22.04.5 (Azure D2s_v5) | x86_64 | gcc 11.4.0 | 2.35 | **10/10** |
| Amazon Linux 2023 | x86_64 | gcc | 2.34 | 5/5 |
| Ubuntu 20.04 | x86_64 | gcc | 2.31 | 5/5 |
| macOS (Apple Silicon) | ARM64 | Apple clang 16.0 | libmalloc | pass |

Build instructions are in the PoC file headers.

### Limitations

- The PoC targets ML-DSA-44 with default build flags. The heap block size and s1 offset differ for ML-DSA-65/87, but the underlying missing-ForceZero bug is the same.
- Heap reuse depends on glibc tcache (deterministic for same-size allocations). Custom `XMALLOC` hooks, non-glibc allocators (musl, jemalloc), or multithreaded applications with intervening allocations may not return the same block.
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

No CVE has been assigned.

---

## Mitigations

If you use wolfSSL with `--enable-mldsa` and cannot update immediately:
- **Isolate signing into a separate process.** The heap reuse requires same-process access. A dedicated signing process with no untrusted co-resident code eliminates the attack surface.
- **Use a zero-on-free allocator.** Custom `XMALLOC`/`XFREE` hooks that zero memory before returning it to the allocator prevent stale data recovery.
- **Enable `WC_DILITHIUM_CACHE_PRIV_VECTORS`.** When caching is on, s1/s2/t0 are stored in the key struct rather than the per-signing scratch block. The scratch block still contains other intermediates but not the full private key polynomials.

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

No CVE assigned.

---

## References

- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) -- Section 3.6.3
- [wolfSSL PR #10100](https://github.com/wolfSSL/wolfssl/pull/10100) -- stack + seedMu fix
- [wolfSSL PR #10113](https://github.com/wolfSSL/wolfssl/pull/10113) -- heap block + seed fix
- [CWE-226](https://cwe.mitre.org/data/definitions/226.html) -- Sensitive Information in Resource Not Removed Before Reuse
- [CWE-244](https://cwe.mitre.org/data/definitions/244.html) -- Improper Clearing of Heap Memory Before Release
