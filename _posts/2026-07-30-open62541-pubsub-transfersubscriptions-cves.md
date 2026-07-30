---
layout: post
title: "Security Flaws in a Major OPC UA Library Used in Critical Infrastructure"
date: 2026-07-30 00:00:00 +0000
categories: [Security, Advisory]
tags: [open62541, opc-ua, iec-62541, ics, ot, pubsub, cve-2026-63362, cve-2026-63035, cwe-191, cwe-416, dos]
description: "Two memory-safety bugs I reported in open62541: an integer underflow in PubSub signature verification and a use-after-free in TransferSubscriptions. Fixed in v1.3.19, v1.4.18 and v1.5.6."
toc: true
pin: true
---

## Summary

[open62541](https://github.com/open62541/open62541) is an open-source implementation of
[OPC UA (IEC 62541)](https://opcfoundation.org/about/opc-technologies/opc-ua/), the interoperability
standard for industrial automation, maintained by
[o6 Automation GmbH](https://www.o6-automation.com/), with
[Fraunhofer IOSB](https://www.iosb.fraunhofer.de/en/projects-and-products/open62541.html) - the
project's original institutional home - now a research partner. It is written entirely in C and
designed to be embedded: controllers, gateways, edge devices.

I reported two memory-safety defects in the protocol-handling code: an integer underflow in PubSub
signature verification that reads far past the end of a buffer, and a use-after-free in the
TransferSubscriptions service. Neither needed valid credentials in the configurations I
tested. The first involves no session at all, though it does need a build with PubSub security
configured. The second needs a session, and the version I tested handed those to anonymous clients
by default.

| CVE | Component | Bug | Impact | CVSS v3.1 · v4 | Fix |
|-----|-----------|-----|--------|----------------|-----|
| [CVE-2026-63362](https://nvd.nist.gov/vuln/detail/CVE-2026-63362) | PubSub signature verification | Unsigned integer underflow ([CWE-191](https://cwe.mitre.org/data/definitions/191.html)) | Out-of-bounds read → DoS | 5.9 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` · 8.2 | 1.3/1.4: [`a1257fee`](https://github.com/open62541/open62541/commit/a1257feec0c539f191cb2d40f72f116a901d3322) · 1.5: [`ba5bf592`](https://github.com/open62541/open62541/commit/ba5bf5928d61e2c8a92b008e2da847722785868f) |
| [CVE-2026-63035](https://nvd.nist.gov/vuln/detail/CVE-2026-63035) | TransferSubscriptions | Use-after-free ([CWE-416](https://cwe.mitre.org/data/definitions/416.html)) | Potential DoS; integrity impact per the advisory (`I:H`) | 8.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` · 7.2 | 1.3: [`2da371bc`](https://github.com/open62541/open62541/commit/2da371bcdaadeb23051635a60e38f31039af9fd8) · 1.4/1.5: [`bc30df3a`](https://github.com/open62541/open62541/commit/bc30df3adab5cc61383cb7e7f551bfd6f7ac160c) |

Coordinated with [CISA](https://www.cisa.gov/), which published the ICS advisory
**[ICSA-26-211-08](https://www.cisa.gov/news-events/ics-advisories/icsa-26-211-08)** on 30 July 2026.

> **Affected:** 1.3.0-1.3.18, 1.4.0-1.4.17 and 1.5.0-1.5.5. The bounds check and the list
> migration first appear in the v1.3.19, v1.4.18 and v1.5.6 tags; I do not find either fix in
> v1.3.18, v1.4.17 or v1.5.5, whereas the advisory's ranges end one release earlier.
> Validated against branch `1.4` at
> commit [`c132505de`](https://github.com/open62541/open62541/commit/c132505de13914c4e6bd77046e3aab09696c068d).
> **Fixed** (27 July 2026) in [v1.3.19](https://github.com/open62541/open62541/releases/tag/v1.3.19),
> [v1.4.18](https://github.com/open62541/open62541/releases/tag/v1.4.18) and
> [v1.5.6](https://github.com/open62541/open62541/releases/tag/v1.5.6) - see [Mitigation](#mitigation).

> **Proof-of-concept code is withheld at o6 Automation's request.** [Why](#why-theres-no-poc-repo-this-time).

---

## Impact

The two are not proven to the same depth. One undersized datagram killed a release build outright,
with no session and no credentials, on a server configured for PubSub signing. The use-after-free
is confirmed memory corruption under a sanitizer, but the uninstrumented server survived my test.

| Demonstrated | Not demonstrated |
|---|---|
| One undersized UDP datagram terminates sanitizer *and* release builds where PubSub security is configured | Default-server exposure for the PubSub flaw - it needs an encryption build and a signing ReaderGroup |
| Cross-platform heap use-after-free write under ASan, through ordinary service calls, in the tested anonymous configuration | A use-after-free crash in an ordinary release build |
| Both defects present through 1.3.18, 1.4.17 and 1.5.5 | Code execution |
| Fixes shipped across all three maintained branches | Exploitation of any named downstream product |

**Why this matters beyond one library.** open62541 is often vendored into a product and compiled
in rather than installed as a package. An upstream release does not update those embedded copies:
someone downstream has to notice it, rebuild, and ship an update of their own, and that can take a
while. That delay is what makes this an industrial problem. o6 notifies device manufacturers and
operators of critical installations directly as part of their vulnerability-management process.

---

## Documented ecosystem footprint

open62541 is designed to be embedded, so most deployments are never disclosed. What follows is
where the code is known to turn up, and who has looked at it. The bullets below document
footprint, not exposure - **none of it is a victim list**, and I did not test those projects or
products for these flaws:

- **Qt** bundles open62541 and builds its
  [QtOpcUa plugin](https://doc.qt.io/qt-6/qtopcua-attribution-open62541.html) against it by
  default.
- **Intel** builds and QA-tests it as part of
  [Edge Controls for Industrial](https://eci.intel.com/docs/2.6/components/tsnrefsw/open62541.html),
  its TSN reference software.
- Germany's **BSI** selected open62541 as the open-source implementation to put through static and
  dynamic code analysis in its
  [2022 OPC UA security study](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPCUA/OPCUA_2022_EN.html).
- Packaged in [Debian, Ubuntu, Fedora, FreeBSD, OpenBSD, nixpkgs, Homebrew and
  more](https://repology.org/project/open62541/versions), plus the embedded build systems -
  [Yocto/OpenEmbedded](https://layers.openembedded.org/layerindex/recipe/336756/) and Buildroot.

### What a downstream library actually compiles in

Sitting inside the affected range doesn't tell you which of these two issues you have. That
depends on what was compiled in and on how the server is configured at runtime, so I unpacked one
library that ships open62541 and checked.

**[Arduino_OPC_UA](https://github.com/arduino-libraries/Arduino_OPC_UA)** (releases 0.1.0-0.1.2,
for Arduino Opta Lite / RS485 / WiFi) pins open62541 at v1.4.0 - inside the affected range - in
its precompile script, and the shipped `libopen62541.a` reports `v1.4.0-dirty`. PubSub is not
compiled in - no `UA_ENABLE_PUBSUB` in the shipped header, no PubSub symbols in the archive - so
the underflow does not apply. `Service_TransferSubscriptions` and
`allowTransferSubscription_default` are present, so the use-after-free code path is compiled. The
bundled server example calls `UA_Server_new()` on port 4840 without customising access control, security or limits. That is
compiled-in code, not a demonstrated exploitable condition on a device.

So the released archive carries the TransferSubscriptions implementation and not PubSub, which is
why build configuration is worth checking before you assume either issue applies to you. Other
potentially affected downstream maintainers have been notified privately and are not named here.

---

## Technical details

Source permalinks are pinned to the tested commit [`c132505de`](https://github.com/open62541/open62541/commit/c132505de13914c4e6bd77046e3aab09696c068d).

### PubSub signature verification underflow (CWE-191)

OPC UA PubSub can sign messages, and `verifyAndDecrypt()` needs to know where the signed region
ends. It computed that by subtracting the signature size from the buffer length
([`ua_pubsub_security.c:84-85`](https://github.com/open62541/open62541/blob/c132505de13914c4e6bd77046e3aab09696c068d/src/pubsub/ua_pubsub_security.c#L84-L85))
without first checking that the buffer was at least as long as the signature.

Both values are unsigned. When a matching message is shorter than the expected signature, the
subtraction does not go negative; it wraps to a value near `SIZE_MAX`. That length goes to the
security policy's signature check. In the tested mbedTLS build, HMAC processing read forward past
the end of the allocation into unmapped memory and the process died.

[The fix](https://github.com/open62541/open62541/commit/a1257feec0c539f191cb2d40f72f116a901d3322)
adds the missing length check.

This one is harder to reach than the other. You need a build with PubSub encryption enabled and a
ReaderGroup in `SIGN` or `SIGNANDENCRYPT` mode, which is not what a default server does. No
session or client authentication is involved, though. The receive path decodes the network-message
headers, matches them against a configured `DataSetReader`, and only then verifies - so a
header-decodable message that matches a reader reaches the subtraction before anything has
established whether its signature is valid. The advisory describes the vector as a crafted UDP
packet, which is what I tested.

If you write C that parses network input, `unsigned_length - constant` is worth grepping for.
Unsigned subtraction wraps modulo the type's range rather than going negative, so it leaves a
well-typed but invalid length that has to be checked against the actual buffer before it is used
as one.

### TransferSubscriptions use-after-free (CWE-416)

`TransferSubscriptions` moves a subscription between sessions - the mechanism a client uses to
resume its subscriptions after reconnecting. The implementation copies the subscription structure
and then re-points its intrusive linked lists at the new owner
([`ua_services_subscription.c`](https://github.com/open62541/open62541/blob/c132505de13914c4e6bd77046e3aab09696c068d/src/server/ua_services_subscription.c#L528)).

Three lists were migrated: monitored items, the notification queue and the retransmission queue. A
fourth, `samplingMonitoredItems`, was not. Its head entry kept an `le_prev` back-pointer into the
original structure, so once that was freed, removing the item wrote through a stale pointer into
freed memory. Under [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) this
surfaces as a heap use-after-free write, reproducible on both macOS arm64 and Linux x86-64. The
uninstrumented release build I ran kept going; I did not demonstrate code execution.

That list only holds items whose sampling interval matches the subscription's publishing interval
([`ua_subscription_monitoreditem.c:724`](https://github.com/open62541/open62541/blob/c132505de13914c4e6bd77046e3aab09696c068d/src/server/ua_subscription_monitoreditem.c#L724));
items sampling on their own timers go elsewhere, so a subscription made up of those never has the
stale pointer at all.

[The fix](https://github.com/open62541/open62541/commit/bc30df3adab5cc61383cb7e7f551bfd6f7ac160c)
migrates `samplingMonitoredItems` with the other lists. Worth noting if you are reviewing a
backport: it has to move the entries, not just `LIST_INIT` the new head. Removing and reinserting
each entry is what rewrites the back-pointer.

The advisory assigns `PR:L`. On the build I tested
([`c132505de`](https://github.com/open62541/open62541/commit/c132505de13914c4e6bd77046e3aab09696c068d)),
anonymous clients could obtain a session and transfer a *detached* subscription - one orphaned when
its session closed - using ordinary service calls: no credentials, no encryption, not even a
malformed message.

That route depended on a separate access-control defect, reported by another researcher and fixed
under o6 advisory SA-2026-0005. Beginning with v1.4.17 and v1.5.5 the anonymous detached-transfer
route was closed, but the list-migration defect stayed reachable through authorized transfers
until v1.4.18 and v1.5.6.

---

## Why there's no PoC repo this time

o6 asked me not to publish runnable proof-of-concept code for these two issues, to protect
installations that may never receive updated firmware. So I didn't.

---

## Checking your own build

- **Find the revision you actually ship.** A vendored copy need not match anything your package
  manager reports.
- **PubSub:** is PubSub encryption compiled in, and does any ReaderGroup use `SIGN` or
  `SIGNANDENCRYPT`? The fix is a `buffer->length < sigSize` check before the subtraction, in
  `ua_pubsub_security.c` on 1.3/1.4 and `ua_pubsub_readergroup.c` on 1.5. A patched build logs
  `PubSub receive. Message too short for signature` instead of reading off the end.
- **TransferSubscriptions:** does the transfer migrate `samplingMonitoredItems` entry by entry?
- **Binaries:** symbols and version strings can show a fix is present, but their absence proves
  nothing in a stripped or inlined build. Under AddressSanitizer the use-after-free surfaces in
  `UA_MonitoredItem_unregisterSampling`; a release build may show nothing at all.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-05-07 | Reported three issues to `open62541-security@googlegroups.com`. |
| 2026-05-11 | Both fixes written - [`a1257fee`](https://github.com/open62541/open62541/commit/a1257feec0c539f191cb2d40f72f116a901d3322) and [`bc30df3a`](https://github.com/open62541/open62541/commit/bc30df3adab5cc61383cb7e7f551bfd6f7ac160c), four days after the report. Held privately. |
| 2026-05-13 | Coordination case opened with CISA. |
| 2026-07-23 / 24 | Fix commits became public. |
| 2026-07-27 | Maintenance releases [v1.3.19](https://github.com/open62541/open62541/releases/tag/v1.3.19), [v1.4.18](https://github.com/open62541/open62541/releases/tag/v1.4.18) and [v1.5.6](https://github.com/open62541/open62541/releases/tag/v1.5.6) published; o6 asked that PoC code not be released; I agreed. |
| 2026-07-30 | CISA advisory published; this post. |

---

## Mitigation

Update to **[v1.5.6](https://github.com/open62541/open62541/releases/tag/v1.5.6)**, **[v1.4.18](https://github.com/open62541/open62541/releases/tag/v1.4.18)** or **[v1.3.19](https://github.com/open62541/open62541/releases/tag/v1.3.19)**, whichever matches your branch. If you cannot move to a tagged release, the upstream fix commits are:
[`a1257fee`](https://github.com/open62541/open62541/commit/a1257feec0c539f191cb2d40f72f116a901d3322)
(PubSub underflow on 1.3/1.4, in `ua_pubsub_security.c`; on 1.5 that file no longer exists and the
equivalent fix is [`ba5bf592`](https://github.com/open62541/open62541/commit/ba5bf5928d61e2c8a92b008e2da847722785868f) in `ua_pubsub_readergroup.c`) and
[`bc30df3a`](https://github.com/open62541/open62541/commit/bc30df3adab5cc61383cb7e7f551bfd6f7ac160c)
(use-after-free on 1.4/1.5; the 1.3 backport is
[`2da371bc`](https://github.com/open62541/open62541/commit/2da371bcdaadeb23051635a60e38f31039af9fd8)).

If you embed open62541 in a product, the version you ship is the version your customers run -
check your vendored copy, not just your build host's package.

Per [CISA guidance](https://www.cisa.gov/topics/industrial-control-systems), keep OPC UA endpoints
off untrusted networks and behind segmentation regardless of version.

---

## Credit

o6 Automation, the maintainers of open62541, confirmed my findings, coordinated them with device
manufacturers and operators of critical installations through its support and
vulnerability-management process, and credited me in the fix commits.

The case was coordinated with CISA, which wrote the advisory and incorporated the technical
corrections I proposed to the draft.

The advisory covers four vulnerabilities: the two above, plus two integer overflows in the
`UA_Variant` arrayDimensions computation - [CVE-2026-65423](https://nvd.nist.gov/vuln/detail/CVE-2026-65423)
(out-of-bounds write) and [CVE-2026-63559](https://nvd.nist.gov/vuln/detail/CVE-2026-63559)
(out-of-bounds read) - reported by **Asher Davila of Palo Alto Networks**.

A third issue in my report had already been reported by **Lorenzo Cannella** and was handled
separately as o6 advisory SA-2026-0002. Credit for that one is his.

---

## References

- CISA advisory: [ICSA-26-211-08](https://www.cisa.gov/news-events/ics-advisories/icsa-26-211-08)
- NVD: [CVE-2026-63362](https://nvd.nist.gov/vuln/detail/CVE-2026-63362) ·
  [CVE-2026-63035](https://nvd.nist.gov/vuln/detail/CVE-2026-63035)
- [CWE-191](https://cwe.mitre.org/data/definitions/191.html) ·
  [CWE-416](https://cwe.mitre.org/data/definitions/416.html)
- Library: [open62541/open62541](https://github.com/open62541/open62541)
- Prior post, for the disclosure-timing comparison:
  [libIEC61850]({% post_url 2026-07-23-libiec61850-mms-goose-cves %}) ·
  [ICSA-26-204-06](https://www.cisa.gov/news-events/ics-advisories/icsa-26-204-06)
- Releases: [v1.5.6](https://github.com/open62541/open62541/releases/tag/v1.5.6) ·
  [v1.4.18](https://github.com/open62541/open62541/releases/tag/v1.4.18) ·
  [v1.3.19](https://github.com/open62541/open62541/releases/tag/v1.3.19)
