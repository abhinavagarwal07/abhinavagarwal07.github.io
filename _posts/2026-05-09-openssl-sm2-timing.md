---
layout: post
title: "OpenSSL's ARM64 SM2 Path Leaks a Private-Key Timing Fingerprint"
date: 2026-05-09 00:00:00 +0000
categories: [Security, Advisory]
tags: [openssl, sm2, timing-side-channel, arm64, riscv, constant-time, ecc, cwe-208]
description: "OpenSSL's optimized SM2 scalar multiplication has data-dependent branches on the private key. Direct measurement of the EC_POINT_mul call used by SM2 decrypt shows r = -0.9828 between runtime and zero-nibble count, with a slope of -389 ns per zero nibble. This leaks a stable aggregate private-key fingerprint (~3 bits) and the same non-constant-time branch pattern may expose richer traces to cache-based attacks. ARM64 and RISC-V only. SM2 is required for systems subject to Chinese commercial cryptography regulations."
toc: true
pin: true
---

## Summary

OpenSSL's optimized SM2 decryption path on ARM64 branches on zero nibbles of the long-term private key scalar. Direct measurement of the `EC_POINT_mul` call used by SM2 decrypt shows **r = -0.9828** correlation between runtime and private key structure, with a slope of **-389 ns per zero nibble**. The x86\_64 generic path shows no comparable signal. This demonstrates leakage of a stable aggregate private-key fingerprint — not full key recovery, but a clear violation of the constant-time property that cryptographic implementations are expected to provide.

SM2 is not an obscure algorithm. It is **required** by Chinese commercial cryptography regulations ([GB/T 32918](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml), [GM/T 0024](https://www.oscca.gov.cn/)) for government information systems, banking networks, telecommunications infrastructure, and IoT devices. The bug affects **ARM64** (measured) and **RISC-V** (same source pattern, unmeasured) — architectures widely used in Chinese cloud and IoT infrastructure. The x86\_64 path is clean.

The P-256 implementation in the same codebase already handles this correctly, using constant-time table lookups and unconditional point operations. The SM2 code does not follow that pattern. A previous CVE ([CVE-2025-9231](https://github.com/openssl/openssl/commit/dff94dba75)) fixed a different timing issue in the same source file but did not modify the scalar multiplication loop.

OpenSSL reviewed this finding and determined it falls outside their [threat model](https://openssl-library.org/policies/general/security-policy/) for same-physical-system side channels. No CVE was assigned.

> **Why this matters:** a long-term private scalar changes OpenSSL's runtime on ARM64. The measured leak is small in entropy terms, but cryptographic scalar multiplication is expected not to branch on secret data at all. This is especially relevant because SM2 is used in Chinese commercial-cryptography deployments and the affected path is an optimized architecture-specific implementation.

> **Affected:** Measured on master commit `5199c5b98a`; the same ARM64 optimized scalar-multiplication code pattern is present in **OpenSSL 3.2.0 through 3.6.1** (introduced in commit `6399d7856c`; absent in 3.1.x). RISC-V compiles the same source path — confirmed by code inspection, not measured. **x86\_64 is not affected.** Check your build: `nm libcrypto.so | grep ecp_sm2p256_point_P_mul` — if the symbol is absent, you are on the generic constant-time path.

---

## Why SM2 Matters

Under GB/T 32918 and GM/T 0024, SM2 is required for systems subject to Chinese commercial cryptography compliance:

- Chinese government information systems
- Banking and financial networks (PBC, UnionPay infrastructure)
- Telecommunications infrastructure ([TLCP](https://datatracker.ietf.org/doc/html/rfc8998) — China's TLS variant)
- IoT devices requiring Chinese cryptographic certification
- Any system subject to commercial cryptography compliance review (密码应用安全性评估)

The optimized code path in `ecp_sm2p256.c` exists specifically because SM2 performance matters on these deployment platforms. Those platforms are predominantly ARM64:

- **Alibaba Cloud** — Yitian 710 (ARM64, custom Neoverse)
- **Huawei Cloud** — Kunpeng 920 (ARM64, HiSilicon)
- **Tencent Cloud** — ARM64 instances available
- **RISC-V** — T-Head C906/C910 (Alibaba), SpacemiT K1, IoT controllers

OpenSSL's security policy excludes same-physical-system side channels from their threat model. That policy is designed for many OpenSSL deployments. But SM2's primary deployment context is cloud infrastructure — where co-tenancy is the architectural norm, not the exception.

---

## The Bug

`ecp_sm2p256_point_P_mul_by_scalar()` (lines 370–414 of [`ecp_sm2p256.c`](https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_sm2p256.c)) processes the 256-bit private key scalar in 4-bit nibble windows. Two branches make execution time depend on the scalar value:

```c
for (i = 64 - 1; i >= 0; --i) {
    index = (k[i / 16] >> (4 * (i % 16))) & mask;  // 4-bit nibble of private key d

    if (init == 0) {
        if (index) {                                  // BRANCH 1: leading zero detection
            memcpy(R, &precomputed[index], sizeof(P256_POINT));
            init = 1;
        }
    } else {
        ecp_sm2p256_point_double(R, R);               // 4x double (always runs)
        ecp_sm2p256_point_double(R, R);
        ecp_sm2p256_point_double(R, R);
        ecp_sm2p256_point_double(R, R);
        if (index)                                    // BRANCH 2: skips point_add when nibble is 0
            ecp_sm2p256_point_add(R, R, &precomputed[index]);
    }
}
```

When a nibble of the private key `d` is zero, `ecp_sm2p256_point_add` is skipped — saving ~389 ns (the cost of 12 field multiplications, 4 squarings, and 7 subtractions in the ARM64 assembly). The `init` flag creates a second signal: leading zero nibbles also skip the 4x doublings, saving even more time.

This function is called during SM2 decryption at [`sm2_crypt.c:360`](https://github.com/openssl/openssl/blob/master/crypto/sm2/sm2_crypt.c#L360) with the long-term **private key `d`** as the scalar. Because `d` is static across the key's lifetime, every decryption reinforces the same signal.

A second function, `ecp_sm2p256_point_G_mul_by_scalar()` (lines 335–364), has the same pattern with 8-bit byte windows for SM2 signing, where it processes the ephemeral nonce `k`.

### P-256 Does This Right. SM2 Doesn't.

The P-256 equivalent in the same codebase ([`ecp_nistz256.c`](https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_nistz256.c)) handles this correctly:

| Property | P-256 (`ecp_nistz256.c`) | SM2 (`ecp_sm2p256.c`) |
|---|---|---|
| Table lookup | `ecp_nistz256_gather_w5/w7` (CT scatter/gather) | `precomputed[index]` (direct array access) |
| Zero-nibble handling | Unconditional `point_add` on every iteration | `if (index)` skips `point_add` |
| Identity handling | `copy_conditional` (branchless cmov) | `is_zeros()` + early-return branch |
| Leading-zero handling | No `init` flag; operates on all windows | `init` flag with data-dependent branching |

This is OpenSSL's own established approach for constant-time scalar multiplication. The SM2 code does not follow it.

---

## Same File as CVE-2025-9231

[CVE-2025-9231](https://github.com/openssl/openssl/commit/dff94dba75) (reported by Stanislav Fort, Aisle Research) fixed a timing vulnerability in the modular inversion path (`get_affine`, `field_inv`, `inv_mod_ord`) in *the same file* — `ecp_sm2p256.c`. That fix replaced three EC\_METHOD vtable entries with constant-time fallbacks. It did not touch the scalar multiplication loop.

All measurements in this post were taken on code that already includes the CVE-2025-9231 fix. The scalar multiplication loop — which processes the private key `d` through 64 iterations of data-dependent branching — was not modified as part of that fix.

---

## What Leaks

### Information Content

For a uniformly random 256-bit key represented as 64 nibbles, the zero-nibble count Z follows a binomial distribution B(64, 1/16) with mean 4. After the attacker learns Z, the remaining keyspace is reduced:

| Z | Remaining keyspace (log₂) | Bits learned |
|---|---|---|
| 0 | 250.0 | **6.0** |
| 2 | 253.2 | 2.8 |
| 4 (most probable) | 253.7 | 2.3 |
| 6 | 252.8 | 3.2 |
| 8 | 250.7 | **5.3** |

**Average information leakage: H(Z) ≈ 3 bits per key lifetime.** Tail-distribution keys (Z = 0 or Z ≥ 7) leak 4–6 bits.

The leading-zero `init` flag provides additional MSB information for ~6% of keys (those with one or more leading zero nibbles). For such keys, the attacker also learns that `d < 2^(256 - 4L)`.

### What This Does NOT Give the Attacker

**Full key recovery from timing alone is not feasible with any published algorithm.** The zero-nibble count is a combinatorial constraint — it tells you *how many* nibbles are zero, not *which*. This does not map to the Hidden Number Problem (HNP) framework used by lattice attacks ([Howgrave-Graham & Smart](https://link.springer.com/chapter/10.1007/3-540-44448-3_12), [Nguyen & Shparlinski](https://link.springer.com/chapter/10.1007/3-540-36413-7_20)), and generic algorithms like Pollard's rho achieve O(2^128) regardless.

### What It Does Give the Attacker

**Key fingerprinting.** The zero-nibble count Z is a coarse timing fingerprint for a private key. Since Z is only ~3 bits, many unrelated keys share the same value — this is not a unique key identifier. However, an attacker observing SM2 decrypt traffic can use it to cluster instances with compatible key profiles and detect some key-rotation events (a change in Z implies a different key).

**Exposure to cache attacks.** The same `if(index)` branch that creates the timing channel also controls whether `precomputed[index]` is accessed — a 1,536-byte table (24 cache lines) on the stack. This branch pattern may expose the implementation to richer traces from cache-based attacks (FLUSH+RELOAD, PRIME+PROBE) by a co-located attacker, which could reveal *which* table entries were accessed per iteration rather than just the aggregate count. This post demonstrates only aggregate timing leakage; per-iteration cache tracing and key recovery are not demonstrated, but the non-constant-time control flow is a precondition for both.

A constant-time fix — branchless table lookup and unconditional point operations, as P-256 already implements — would eliminate both channels simultaneously.

### SM2 Signing: The Minerva Parallel

The signing path (`point_G_mul_by_scalar`) processes the ephemeral nonce `k` in 8-bit byte windows. This is the same *class* of vulnerability as [Minerva](https://minerva.crocs.fi.muni.cz/) (CVE-2019-15809, CVE-2024-13176): non-constant-time processing of a cryptographic nonce. The specific leakage geometry here is less favorable for lattice exploitation than Minerva's (zero-byte *count* rather than nonce bit-length), and no published lattice construction converts this leakage type into an HNP attack. However, a novel construction handling scattered Hamming weight constraints — an open research problem — could change this assessment.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-05-02 | Reported to openssl-security@openssl.org with full evidence (correlation data, 4 independent PoCs, negative controls, CT patch) |
| 2026-05-06 | OpenSSL response: decided to handle as a regular bug/hardening issue, no CVE. Asked for a public GitHub issue. |
| 2026-05-09 | Public disclosure (this post) |

OpenSSL's response was consistent with their stated [security policy](https://openssl-library.org/policies/general/security-policy/), which explicitly excludes same-physical-system side channel attacks from their threat model. The policy notes: *"Prior to the threat model being included in this policy, CVEs were sometimes issued for these classes of attacks. The existence of a previous CVE does not override this policy going forward."*

---

## Practical Guidance

**Check if you're affected:**

```bash
nm libcrypto.so | grep ecp_sm2p256_point_P_mul
```

If the symbol is present, the non-constant-time optimized path is compiled in. If absent (x86\_64), the generic constant-time EC path is used.

**Who should act:**

- Organizations running SM2 decryption services on ARM64 or RISC-V
- Cloud providers offering SM2-based TLS/TLCP endpoints on ARM64 infrastructure
- IoT deployments using SM2 on RISC-V with physical attacker exposure

**Mitigation:** The fix is the same approach P-256 already uses: constant-time table lookup (`gather_w5`-style scatter/gather), unconditional point operations on every loop iteration, and branchless identity handling via conditional-move. A public GitHub issue will be filed.

---

## Technical Details

### Measurement Setup

All measurements on ARM64 (Neoverse-N1, Azure Standard\_D4ps\_v5, 4 vCPUs, pinned to core 0, Ubuntu 22.04). OpenSSL 4.1.0-dev built from commit `5199c5b98a`.

Each key was measured using 2,000 SM2 decrypt operations with the `EVP_PKEY_CTX` created once and reused (eliminating context-creation overhead). 50 warmup calls were discarded. The P20 (20th percentile) of the remaining 1,950 measurements was used as the per-key timing estimate. Measurement order was randomized using Fisher-Yates shuffle to eliminate ordering artifacts.

### Core Result: Direct EC\_POINT\_mul Isolation

100 crafted keys spanning 0–49 zero nibbles, no EVP overhead, Fisher-Yates randomized:

- **Pearson r = -0.9828** (t = -52.61)
- **Slope = -389.4 ns/zero-nibble**
- Timing range: 23,114 ns (51,401–74,515 ns)
- Ratio to EVP measurement: 0.957 — confirming the signal originates in scalar multiplication, not EVP context

This is the cleanest measurement: it isolates the exact `EC_POINT_mul` call used by SM2 decrypt, with no EVP/KDF/SM3 overhead.

### Blind Hidden-Key Inference

The attacker has **no access** to the private key. Keys are generated, a fixed plaintext is encrypted with the public key, and the attacker infers key structure from `EVP_PKEY_decrypt` timing alone.

**Broad range** (40 keys, 0–50 zero nibbles, 4 buckets):

- Accuracy within ±2 nibbles = **80%**, MAE = 1.73

**Natural range** (20 keys from `EC_KEY_generate_key`, 0–8 zero nibbles):

- **20/20 correct within ±2 nibbles (100%)**, MAE = **0.1**

### Extreme-Key Sanity Check

Using artificially crafted keys at the extremes (0 vs 63 zero nibbles): timing gap of **165.8 µs**, Welch t = 2,748. These are not realistic keys but confirm the linear relationship between zero-nibble count and timing across the full range.

### Negative Controls

**x86\_64 SM2 (Intel Cascade Lake, same PoC):** `nm libcrypto.so | grep sm2p256_point_P_mul` returns nothing — the optimized function is absent from x86 builds.

| Phase | ARM64 (SM2) | x86\_64 (control) |
|---|---|---|
| Correlation r | -0.9828 | **0.152** (no signal) |
| Hidden-key accuracy | 80% | **5%** (random chance) |
| Natural-key r | -0.9829 | **-0.077** (no signal) |

As an auxiliary harness sanity check, P-256 ECDH on the same ARM64 hardware showed r = 0.096 (no correlation, slope = 0.2 ns/nibble — noise floor). This uses a different API path (ECDH, not decrypt) but confirms the measurement infrastructure does not produce false positives.

### Patch Status

An initial constant-time table-lookup patch eliminated the timing gap between a controlled pair of keys (Welch t: 240.98 → -0.29, 2.6% overhead). However, broader testing across 100 keys showed the correlation persisted at r = -0.97, because `ecp_sm2p256_point_add()` and `ecp_sm2p256_point_double()` also contain identity-dependent early returns (lines 186, 286, 294, 302) that leak through a separate mechanism. A complete fix must make the point arithmetic functions branchless as well — a fully branchless patch using `constant_time_select` has been written but not yet measured.

---

## Evidence Artifacts

PoC source code, evidence tarballs, and measurement transcripts are available on request.

| Artifact | Description |
|---|---|
| `poc_sm2_ecmul_direct.c` | Direct `EC_POINT_mul` isolation — proves signal is in scalar mul, not EVP |
| `poc_sm2_airtight.c` | Full 3-phase PoC: shuffled correlation, blind inference, random keygen |
| `poc_sm2_hidden_key.c` | Blind hidden-key inference via `EVP_PKEY_decrypt` |
| ARM64 evidence tarball | Neoverse-N1 measurements, compiler flags, build log |
| x86 evidence tarball | Intel Cascade Lake negative control |
| CT patch evidence tarball | A/B patched vs unpatched comparison |
