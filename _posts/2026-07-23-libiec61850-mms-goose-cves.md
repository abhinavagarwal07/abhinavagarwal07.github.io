---
layout: post
title: "Patched in Public, Disclosed 76 Days Later: Four Unauthenticated Flaws in libIEC61850"
date: 2026-07-23 00:00:00 +0000
categories: [Security, Advisory]
tags: [libiec61850, iec-61850, ics, ot, mms, goose, cve-2026-49035, cve-2026-50039, cve-2026-50032, cve-2026-50103, cwe-122, cwe-121, cwe-476, rce, dos]
description: "Four unauthenticated flaws in libIEC61850, the IEC 61850 stack behind substation MMS and GOOSE — one chained to RCE in a lab, three reliable crashes. Their fixes remained on a public development branch for 76 days before the coordinated CISA advisory (ICSA-26-204-06). Fixed in v1.6.2."
toc: true
pin: true
---

## Summary

[libIEC61850](https://github.com/mz-automation/libiec61850) is a widely used open-source implementation
of the IEC 61850 protocol suite — MMS (client/server SCADA over TCP/102), GOOSE (Layer-2 protection
signaling), and Sampled Values. It targets embedded systems and, per the vendor, has been used in many
commercial software products and devices; in IEC 61850 deployments this code sits directly in the path
of substation telemetry, operator commands, and protection signaling.

I found four unauthenticated vulnerabilities affecting v1.0.0 through v1.6.1, all sitting in
unauthenticated protocol paths: the MMS server binds `INADDR_ANY` on TCP/102 with no authenticator by
default, and GOOSE subscribers process frames straight off the wire. One is a heap overflow I chained
from MMS ObtainFile to FileRead and **demonstrated as end-to-end command execution** — in a deliberately
unhardened lab build (AArch64, non-PIE, ASLR off). Treat that as a **lab RCE chain**, not a universal
RCE. The other three produce reliable **process crashes**: a single GOOSE frame, or one MMS request
after association.

One wrinkle, and it isn't a knock on the maintainer — who responded fast: fixes for **all four** landed
on a public GitHub branch the day after my report. But with no release and no public advisory for
**76 days** (the CVE IDs were reserved a month in, but a reserved CVE is not a warning), those commits
were a ready-made roadmap for anyone watching the repo, while operators watching for releases saw
nothing. See [Fixed in public, before the advisory](#fixed-in-public-before-the-advisory).

| CVE | Component | Bug | Impact | CVSS v3.1 / v4 |
|-----|-----------|-----|--------|----------------|
| [CVE-2026-49035](https://nvd.nist.gov/vuln/detail/CVE-2026-49035) | MMS file service | Heap overflow via integer underflow (CWE-122/191) | **RCE** (unhardened lab build) / DoS | 8.1 / 9.2 |
| [CVE-2026-50039](https://nvd.nist.gov/vuln/detail/CVE-2026-50039) | MMS value cache | Stack overflow, unbounded copy (CWE-121) | DoS | 7.5 / 8.7 |
| [CVE-2026-50032](https://nvd.nist.gov/vuln/detail/CVE-2026-50032) | MMS write service | NULL deref on empty `listOfData` (CWE-476) | DoS | 7.5 / 8.7 |
| [CVE-2026-50103](https://nvd.nist.gov/vuln/detail/CVE-2026-50103) | GOOSE / R-GOOSE parser | NULL deref on malformed TLV (CWE-476/228) | DoS | 6.5 / 7.1 |

Coordinated through CISA: **[ICSA-26-204-06](https://www.cisa.gov/news-events/ics-advisories/icsa-26-204-06)** /
CERT/CC **VU#372281**. PoC code: **[github.com/abhinavagarwal07/libiec-security-poc](https://github.com/abhinavagarwal07/libiec-security-poc)**.

> **Affected:** libIEC61850 **v1.0.0 through v1.6.1**. Validated against commit `a1396111` (v1.6.1
> tip). **All four fixed in v1.6.2** — see [Mitigation](#mitigation).

> **Disclosure:** Reported to the vendor (MZ Automation) and coordinated through CERT/CC (VU#372281)
> and CISA. This write-up and the PoC code are published after the CISA advisory, with CISA's go-ahead.
> No known public exploitation has been reported as of publication.

---

## Impact

These bugs sit in the control-plane software of the power grid. Here is what I demonstrated, and what it
means for a deployment running an affected build:

| Path | Demonstrated | Potential operational consequence (deployment-dependent) |
|------|--------------|----------------------------------------------------------|
| MMS FileRead (CVE-2026-49035) | Unauthenticated command execution in a deliberately unhardened lab build (AArch64, non-PIE, ASLR off, writable GOT) | Control of whatever the affected process exposes — telemetry/configuration manipulation, forged measurements or commands, lateral movement — depending on privileges |
| MMS value-cache / write (CVE-2026-50039 / -50032) | Repeatable crash of the MMS server process | Loss of the measurement and command handling that process provides until recovery; repeated requests can prolong the outage |
| GOOSE parser (CVE-2026-50103) | Crash of a subscribing application when its callback dereferences the malformed dataset | Interruption of trip/interlock processing *if* that application performs a protection role and lacks redundancy or fail-safe behavior |

### What RCE means in a library like this

A crash is a loss of availability; code execution is a loss of the device. IEC 61850 endpoints are not
peripheral — they are the relays, bay controllers, and gateways that measure the primary plant and carry
operator and protection commands. Code execution on one lets an attacker do far more than deny service:
forge or suppress the telemetry an operator sees, issue or block breaker and switch operations, alter
protection settings so the scheme mis-operates or fails to act on a real fault, persist across restarts,
and pivot across the substation LAN to other IEC 61850 devices. Loss of view, loss of control, and
protection that does not operate on demand are exactly the scenarios ICS operators plan against — which
is why unauthenticated memory corruption is far worse here than in a desktop parser. What I demonstrated
is `execve` from the server process in a lab; the distance from there to those outcomes is deployment
engineering, not a second vulnerability.

---

## Documented ecosystem footprint

libIEC61850 targets embedded systems and, per the vendor, has been used in many commercial software
products and devices; GPLv3-or-commercial licensing means most embeddings are never disclosed. The
public pointers below are **footprint, not a victim list** — none establishes that a named party runs a
vulnerable version, an affected configuration, or is impacted by these bugs:

- LF Energy documents a first-substation **[FledgePower](https://lfenergy.org/lf-energy-summit-recap-and-video-an-intelligent-edge-for-energy-automation-fledgepower-in-rte-substations-jeas-iiot-61850/)**
  rollout at **RTE** (French TSO); FledgePower's IEC 61850 south plugin
  ([`fledge-south-iec61850`](https://github.com/fledge-power/fledge-south-iec61850)) builds against libIEC61850.
- **[OpenPLC61850](https://www.sciencedirect.com/science/article/pii/S235271102100162X)** (a peer-reviewed
  open-source PLC), **[VILLASframework](https://villas.fein-aachen.org/docs/node/nodes/iec61850-8-1/)**
  (RWTH Aachen), and **[json-scada](https://github.com/riclolsen/json-scada)** embed it for MMS/GOOSE.
- Claroty's Team82 lists libIEC61850 among the
  [popular MMS stacks](https://claroty.com/team82/research/mms-under-the-microscope-examining-the-security-of-a-power-automation-standard)
  it fingerprinted on internet-facing devices.
- **Alliander** (Dutch DSO) published two now-archived open-source projects built on the library —
  [`der-scheduling`](https://github.com/alliander-opensource/der-scheduling) and
  [`ReLevENT`](https://github.com/alliander-opensource/ReLevENT).

### Prior art

This library has a documented multi-year history of ICS-critical memory-corruption bugs. CISA advisory
[ICSA-22-251-01](https://www.cisa.gov/news-events/ics-advisories/icsa-22-251-01) covered Claroty-reported
[CVE-2022-2970/2971/2972/2973](https://nvd.nist.gov/vuln/detail/CVE-2022-2972) — two stack overflows
scored **CVSS 10.0** (RCE-capable), a type confusion, and a NULL deref. ENCS later reported
CVE-2024-45969/45970/45971 in the MMS client. The four bugs here continue that pattern, including a new
end-to-end RCE chain through the MMS file service.

---

## Fixed in public, before the advisory

This part is less about the vendor than about a structural gap operators should understand. The
maintainer responded fast: on **2026-05-08** — the day after I reported the issues (2026-05-07), and
before the CERT/CC case was even opened (2026-05-09) — fixes for **all four** were committed to the
**public** `v1.6_develop` branch, with commit messages that state plainly what they fix:

- [`db35acf6`](https://github.com/mz-automation/libiec61850/commit/db35acf6) — *"added check for
  minimum PDU size… also fixes a potential buffer underflow issue with the file service when the client
  connects and proposes a PDU size < 20"* (the RCE, CVE-2026-49035).
- [`a0bd0aaa`](https://github.com/mz-automation/libiec61850/commit/a0bd0aaa) — *"fixed unbounded string
  copy in MmsValueCache_lookupValue"* (CVE-2026-50039).
- [`62f22887`](https://github.com/mz-automation/libiec61850/commit/62f22887) — *"Some data types in
  parsing an unknown GOOSE dataset are not length validated"* (CVE-2026-50103).
- [`bd338f23`](https://github.com/mz-automation/libiec61850/commit/bd338f23) — *"fixed missing Data
  element number validation in write data set server"* (CVE-2026-50032).

Fixing quickly is the right instinct. The gap is what happened next: for **76 days** there was no
release and no public advisory — only public commits that name the vulnerabilities. (The CVE IDs were
reserved about a month in, but a reserved CVE is no notice to operators.) Anyone watching the repository
could read those messages and diff the commits to see which parsing paths were now bounds-checked — a
weaponization lead on an unauthenticated RCE and three unauthenticated DoS conditions, **before** any
release or advisory reached defenders. Operators tracking releases saw nothing; anyone tracking commits
had a head start. Security-relevant fixes need a coordinated release and advisory close behind the
commits; here they trailed by 76 days.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-05-07 | Reported the four issues to the vendor (MZ Automation), who acknowledged all four as reasonable. |
| **2026-05-08** | **The next day**, the vendor committed fixes for **all four** to the **public** `v1.6_develop` branch ([`db35acf6`](https://github.com/mz-automation/libiec61850/commit/db35acf6), [`a0bd0aaa`](https://github.com/mz-automation/libiec61850/commit/a0bd0aaa), [`62f22887`](https://github.com/mz-automation/libiec61850/commit/62f22887), [`bd338f23`](https://github.com/mz-automation/libiec61850/commit/bd338f23)) — the commit messages named the bugs; no release or advisory. See [Fixed in public, before the advisory](#fixed-in-public-before-the-advisory). |
| 2026-05-09 | CERT/CC coordination case **VU#372281** opened. |
| 2026-06-09 | CVEs reserved (CVE-2026-49035 / -50039 / -50032 / -50103). |
| 2026-06-14 | Submitted detailed reports to CISA; demonstrated CVE-2026-49035 as end-to-end RCE (beyond the original ASAN crash). |
| 2026-06-15 | CISA (ICS VMC) updated the advisory draft. |
| 2026-06-16 | Reviewed the draft; suggested RCE/CVSS and mitigation refinements. |
| 2026-06-28 | Sent Alliander (Dutch DSO) a precautionary notification concerning two archived open-source projects referencing the library. |
| 2026-07-23 | CISA advisory ICSA-26-204-06 published; this post and the PoC repo made public. |

---

## Technical details

Root cause and reachability for each finding, most severe first. Source permalinks are pinned to the
tested commit `a1396111`.

### CVE-2026-49035 — unauthenticated MMS FileRead heap overflow (lab RCE chain)

The lead bug. During MMS Initiate the server reads `maxPduSize` from the client and clamps only the
**upper** bound ([`mms_association_service.c`](https://github.com/mz-automation/libiec61850/blob/a13961110b/src/mms/iso_mms/server/mms_association_service.c#L360-L363)):

```c
self->maxPduSize = BerDecoder_decodeUint32(buffer, length, bufPos);
if (self->maxPduSize > CONFIG_MMS_MAXIMUM_PDU_SIZE)
    self->maxPduSize = CONFIG_MMS_MAXIMUM_PDU_SIZE;   /* no minimum check */
```

The FileRead response path then computes a chunk size by subtracting a fixed header budget
([`mms_file_service.c:834`](https://github.com/mz-automation/libiec61850/blob/a13961110b/src/mms/iso_mms/server/mms_file_service.c#L834)):

```c
uint32_t maxFileChunkSize = maxPduSize - 20;   /* underflows when maxPduSize < 20 */
```

With `maxPduSize = 1`, `maxFileChunkSize` wraps to `0xFFFFFFED` (~4 GB). The subsequent guard
`bytesLeft > maxFileChunkSize` is now always false, so `fileChunkSize` is set to the **entire file
size** and the file is copied into a fixed **65,100-byte heap buffer**:

```c
if (bytesLeft > maxFileChunkSize) fileChunkSize = maxFileChunkSize;   /* skipped */
else fileChunkSize = bytesLeft;                                        /* = whole file */
...
FileSystem_readFile(frsm->fileHandle, buffer + bufPos, fileChunkSize);  /* heap overflow */
```

A file larger than ~65 KB overflows the buffer. The catch: FileRead needs a file to read — but the
default build enables the MMS **ObtainFile** service (`MMS_OBTAIN_FILE_SERVICE 1`), which lets an
unauthenticated client **stage** a file of its choosing onto the server first. Nothing pre-existing is
required.

#### From overflow to code execution

The [`rce/`](https://github.com/abhinavagarwal07/libiec-security-poc/tree/main/CVE-2026-49035-mms-fileread-heap-rce/rce)
harness in the PoC repo runs the full chain in Docker and proves it end to end:

1. Connect, negotiate `maxPduSize = 1` (underflow armed).
2. Stage a ~120 KB crafted payload via ObtainFile (network only, no auth).
3. FileRead triggers the overflow, corrupting an adjacent COTP connection structure.
4. The corrupted state makes the server read 4 attacker-supplied bytes into `free@GOT`.
5. The attacker sends the address of `system()`; connection cleanup calls `free()` → `system(cmd)`.

Proof of execution is a nonce-stamped file written by the server process plus an `strace` capture of
`execve("/bin/sh", ["sh","-c", ...])` from a child of the server. A patched build (minimum-PDU
enforcement) is run as a negative control and does not trigger.

The harness (`rce/run.sh` + Dockerfile, ~2 min with Docker + Python 3) is self-contained on native
AArch64 Linux — the Dockerfile clones libIEC61850 at the pinned commit itself. Docker must grant
`SYS_PTRACE` for the included `strace` proof. ASLR is disabled per process inside the container via
`setarch -R`, so the host is untouched. The hard-coded offsets reproduce the `system()` result only in
that captured AArch64 environment.

> **Conditions for the full RCE:** the demonstrated chain is specific to a deliberately unhardened lab
> build and stacks several assumptions — a **non-PIE** binary, **ASLR disabled**, a **writable GOT** (no
> full RELRO), a **deterministic allocator/object layout**, and **AArch64-specific** offsets (the exact
> harness config: AArch64, `cmake` build linked `-no-pie`, verified with `readelf`; per-process
> ADDR_NO_RANDOMIZE). Restore any of those — PIE, full ASLR, full RELRO, a different architecture — and
> the same bug is a reliable unauthenticated **DoS** that would additionally need an info-leak (and more) to
> reach code execution, which I did not demonstrate. The overflow needs no hardening bypass to crash the
> server, but it does require the MMS file service to be reachable and a large-enough file to read —
> which the default ObtainFile service can stage.

### CVE-2026-50039 — MMS value-cache stack overflow

`MmsValueCache_lookupValue()` copies a variable path into a 65-byte stack buffer with an unbounded
copy ([`mms_value_cache.c:149-150`](https://github.com/mz-automation/libiec61850/blob/a13961110b/src/mms/iso_mms/server/mms_value_cache.c#L149-L150)):

```c
char itemIdCopy[65];
StringUtils_copyStringToBuffer(itemId, itemIdCopy);   /* memcpy(dst, src, strlen(src)+1) — no bound */
```

An unauthenticated MMS ReadRequest with AlternateAccess for a model component whose full path exceeds
64 characters overflows the buffer. IEC 61850-7-2 allows 32-character names per hierarchy level, so
standard-compliant multi-level object references pass 64 characters easily, and paths are enumerable
via `GetNameList`. On a canary-instrumented build the stack canary aborts the process (DoS). On the tested
x86-64 configuration the demonstrated effect is stack corruption and a crash — saved-state control (the
return address) was not reached at the tested path length, so further exploitability is plausible but
unproven. The sibling
`MmsValueCache_lookupValueEx()` in the same file uses the bounded `StringUtils_copyStringMax(..., 65, ...)`;
this base function does not. Reachability is **conditional on the deployed model** carrying a >64-char
path — but the unbounded copy is a defect regardless.

### CVE-2026-50032 — MMS Write NVL NULL dereference

When a WriteRequest targets a Named Variable List, `createWriteNamedVariableListResponse()` iterates
over the server-side member list but never checks that the client's `listOfData` count matches
([`mms_write_service.c`](https://github.com/mz-automation/libiec61850/blob/a13961110b/src/mms/iso_mms/server/mms_write_service.c#L343-L411)):

```c
int numberOfWriteItems = LinkedList_size(variables);
/* missing guard: writeRequest->listOfData.list.count != numberOfWriteItems */
for (element = ...; element != NULL; element = ...) {
    Data_t* dataElement = writeRequest->listOfData.list.array[i];   /* array == NULL → SEGV */
```

An empty `listOfData` (`A0 00`) is accepted by the decoder, leaving `list.array == NULL`; the loop
dereferences it. The sibling `listOfVariable` path has exactly this count guard
([line 646](https://github.com/mz-automation/libiec61850/blob/a13961110b/src/mms/iso_mms/server/mms_write_service.c#L646)) —
the `variableListName` path does not. One crafted WriteRequest, after a normal MMS association, crashes
the server. Requires at least one Named Variable List to be defined in the model.

### CVE-2026-50103 — GOOSE/R-GOOSE parser NULL dereference

`parseAllDataUnknownValue()` parses a GOOSE dataset in two passes: pass 1 allocates a slot per
recognized tag, pass 2 fills it. For three tag types the value is assigned **only inside** a
length check ([`goose_receiver.c:665-703`](https://github.com/mz-automation/libiec61850/blob/a13961110b/src/goose/goose_receiver.c#L665-L703)):

| Tag | Type | Valid lengths |
|-----|------|---------------|
| `0x87` | Float | 5, 9 |
| `0x8c` | BinaryTime | 4, 6 |
| `0x91` | UTCTime | 8 |

A frame carrying one of these tags with a wrong length leaves the slot `NULL`. The dataset — NULL
element included — is handed to the subscriber callback, and `MmsValue_getType(NULL)` dereferences
`0x0`. A single malformed GOOSE frame crashes a subscriber whose callback assumes non-NULL dataset
elements — a common pattern.

**Potential shared R-GOOSE code path.** Native GOOSE is Layer-2 (adjacent attacker). Source review
indicates the same `parseAllDataUnknownValue()` parser is also used by the library's **beta** R-GOOSE
(Routable GOOSE over UDP) implementation, so the defect may extend there. I did not test R-GOOSE;
whether a malformed frame actually reaches the parser over UDP would also depend on R-session handling,
any IEC 62351 protection, and subscriber configuration. Treat this as an unverified shared-code-path
observation, not a demonstrated routable attack.

---

## Suggested CVSS

| CVE | Vector (v3.1) | Score | Notes |
|-----|---------------|-------|-------|
| CVE-2026-49035 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 | AC:H reflects the ObtainFile staging + memory-corruption chain; RCE shown with ASLR off. |
| CVE-2026-50039 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 | A:H; conditional on a model with >64-char paths. |
| CVE-2026-50032 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 | One crafted request, post-association. |
| CVE-2026-50103 | `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 6.5 | AV:A for L2 GOOSE; R-GOOSE/UDP may raise the vector. |

---

## Reproducing

Full harnesses, vulnerable-server builds, patch diffs, and negative controls are in the PoC repo, and
run from a standalone clone. `setup.sh` fetches the pinned libIEC61850 source for the crash harnesses;
the RCE harness is self-contained (its Dockerfile clones the library). Run in a disposable VM.

```bash
git clone https://github.com/abhinavagarwal07/libiec-security-poc && cd libiec-security-poc

# CVE-2026-49035 — end-to-end RCE (native AArch64 Linux; Docker; per-process ASLR off)
( cd CVE-2026-49035-mms-fileread-heap-rce/rce && bash run.sh )

# The three crash PoCs — fetch the pinned library once, then build any of them
./setup.sh && export LIBIEC61850_SRC="$PWD/.libiec61850"
( cd CVE-2026-50032-mms-write-nvl-null/poc     && ./build.sh && ./run_poc.sh )  # NULL-deref DoS
( cd CVE-2026-50039-mms-valuecache-stack-bof/poc && ./build.sh && ./run_poc.sh )  # stack overflow
( cd CVE-2026-50103-goose-null-deref/poc       && ./build.sh && ./run_poc.sh )  # GOOSE NULL-deref
```

---

## Mitigation

Update to **libIEC61850 v1.6.2**, the maintainer's fixed release, which ships all four `v1.6_develop`
fixes: CVE-2026-49035 ([`db35acf6`](https://github.com/mz-automation/libiec61850/commit/db35acf6)),
CVE-2026-50039 ([`a0bd0aaa`](https://github.com/mz-automation/libiec61850/commit/a0bd0aaa)),
CVE-2026-50103 ([`62f22887`](https://github.com/mz-automation/libiec61850/commit/62f22887)), and
CVE-2026-50032 ([`bd338f23`](https://github.com/mz-automation/libiec61850/commit/bd338f23)). If you
cannot yet move to a tagged release, the four fix commits (or the `patch_*.diff` files in the PoC repo)
apply cleanly to v1.6.1.

Regardless of version, per CISA guidance keep IEC 61850 / MMS off untrusted networks: segment substation
LANs, place devices behind firewalls isolated from business networks, and require VPNs for remote access.

---

## References

- CISA advisory: [ICSA-26-204-06](https://www.cisa.gov/news-events/ics-advisories/icsa-26-204-06) · CERT/CC [VU#372281](https://kb.cert.org/vuls/id/372281)
- NVD: [CVE-2026-49035](https://nvd.nist.gov/vuln/detail/CVE-2026-49035) ·
  [CVE-2026-50039](https://nvd.nist.gov/vuln/detail/CVE-2026-50039) ·
  [CVE-2026-50032](https://nvd.nist.gov/vuln/detail/CVE-2026-50032) ·
  [CVE-2026-50103](https://nvd.nist.gov/vuln/detail/CVE-2026-50103)
- [CWE-122](https://cwe.mitre.org/data/definitions/122.html) ·
  [CWE-191](https://cwe.mitre.org/data/definitions/191.html) ·
  [CWE-121](https://cwe.mitre.org/data/definitions/121.html) ·
  [CWE-476](https://cwe.mitre.org/data/definitions/476.html)
- PoC artifacts: [github.com/abhinavagarwal07/libiec-security-poc](https://github.com/abhinavagarwal07/libiec-security-poc)
- Library: [mz-automation/libiec61850](https://github.com/mz-automation/libiec61850)
