---
layout: post
title: "RingWraith: Summary"
date: 2026-03-24 12:00:00 +0000
categories: [Security]
tags: [cve-2026-33150, cve-2026-33179]
description: "Press summary for RingWraith — CVE-2026-33150 and CVE-2026-33179 in libfuse io_uring."
toc: false
pin: false
---


**Two memory safety CVEs in libfuse's brand-new io_uring transport, triggered by standard container security hardening.**

---

A use-after-free and a NULL pointer dereference in [libfuse](https://github.com/libfuse/libfuse)'s io_uring integration — the reference FUSE userspace library for Linux — were discovered and fixed in March 2026. The bugs were present in libfuse 3.18.0 and 3.18.1, the only two releases with io_uring support before the fix. The attack surface will grow as distributions adopt libfuse 3.18+.

**The impact:** A FUSE daemon using io_uring can crash during shutdown — or worse, operate on freed memory that may have been overwritten, opening the door to potential code execution. The bug is triggered when container resource limits (a standard security practice) cause io_uring startup to fail. The error handler frees memory but keeps a stale pointer, which is later dereferenced. See the [full technical writeup](/posts/ringwraith/) for root cause analysis, exploitation surface, and PoC.

**Why io_uring matters here:** Google [disclosed](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html) that 60% of kernel exploit submissions to their kCTF VRP targeted io_uring. They disabled it on ChromeOS and production servers, and restricted it on Android via seccomp-bpf. libfuse's first io_uring release shipped with a UAF in the startup error path.

libfuse has had only [9 CVEs in its first ~24 years](https://repology.org/project/libfuse/cves) (2001–2025) — an 8-year gap before these two. The io_uring integration broke that streak on its first release.

---

| | CVE-2026-33150 | CVE-2026-33179 |
|---|---|---|
| **Type** | Use-After-Free | NULL Deref + Memory Leak |
| **CVSS** | 7.8 HIGH | 5.5 MEDIUM |
| **Impact** | Crash (DoS), theoretical code execution via heap reuse | Crash (DoS via NULL deref), filesystem hang (via error swallowed as success) |
| **Affected** | libfuse 3.18.0 – 3.18.1 | libfuse 3.18.0 – 3.18.1 |
| **Fixed in** | [libfuse 3.18.2](https://github.com/libfuse/libfuse/releases/tag/fuse-3.18.2) | [libfuse 3.18.2](https://github.com/libfuse/libfuse/releases/tag/fuse-3.18.2) |

**Reporter:** [Abhinav Agarwal](https://github.com/abhinavagarwal07), Sr. Software Developer at [Rubrik](https://www.rubrik.com)

---

### Links

- **Full technical writeup:** [RingWraith: The Complete Analysis](/posts/ringwraith/)
- **oss-security disclosure:** [openwall.com/lists/oss-security/2026/03/21/2](https://www.openwall.com/lists/oss-security/2026/03/21/2)
- **GitHub Advisories:** [GHSA-qxv7-xrc2-qmfx](https://github.com/libfuse/libfuse/security/advisories/GHSA-qxv7-xrc2-qmfx) (UAF) · [GHSA-x669-v3mq-r358](https://github.com/libfuse/libfuse/security/advisories/GHSA-x669-v3mq-r358) (NULL deref)
- **NVD:** [CVE-2026-33150](https://nvd.nist.gov/vuln/detail/CVE-2026-33150) · [CVE-2026-33179](https://nvd.nist.gov/vuln/detail/CVE-2026-33179)
- **Fix commits:** [9eba0f3](https://github.com/libfuse/libfuse/commit/9eba0f3) (UAF) · [26ee54a](https://github.com/libfuse/libfuse/commit/26ee54a) (NULL deref)

### Contact

Abhinav Agarwal · abhinav [dot] agarwal [at] rubrik [dot] com · [GitHub](https://github.com/abhinavagarwal07)
