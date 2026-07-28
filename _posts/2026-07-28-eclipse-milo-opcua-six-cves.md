---
layout: post
title: "A Captured Login and a Padding Oracle: Recovering OPC UA Passwords in Eclipse Milo, the Stack Behind Industrial IoT"
date: 2026-07-28 00:00:00 +0000
categories: [Security, Advisory]
tags: [eclipse-milo, opc-ua, iec-62541, ics, ot, industrial-iot, padding-oracle, bleichenbacher, denial-of-service, authorization-bypass, cwe-204, cwe-401, cwe-862, cwe-863]
description: "A CVSS 4.0 9.1 padding oracle in Eclipse Milo — the open-source OPC UA stack embedded across industrial IoT — lets an on-path attacker recover a user's OPC UA password from a single captured token. It is the sharpest of six server-side flaws, alongside an unauthenticated remote crash and an RBAC bypass. Fixed in 1.1.5."
toc: true
pin: true
---

## Summary

[Eclipse Milo](https://github.com/eclipse-milo/milo) is a widely used open-source implementation
of **OPC UA (IEC 62541)** for the JVM — the client/server SDK that industrial software reaches for when it
needs to speak the protocol that ties together SCADA, MES, historians, and the Industrial IoT. It is
embedded in downstream products across the industrial software stack — integration frameworks, historians,
and IIoT connectors all pull it in. When Milo runs as a server, it sits on the wire between OT clients and the process
data, commands, and identities they exchange.

I reported six server-side vulnerabilities in Milo. All are network-reachable; several are
**pre-authentication**. The strongest is a **padding oracle that recovers a user's OPC UA password** (CVSS 4.0 9.1 Critical;
CVSS 3.1 7.4) from a single captured token; the most broadly exposed is an **unauthenticated remote crash**
that takes down the whole server process with no credentials and no session. All six are fixed in
**Eclipse Milo 1.1.5**.

| Finding | Component | Bug | Impact | CVSS 3.1 / 4.0 |
|-----|-----------|-----|--------|----------------|
| Padding oracle | Username-token (`Basic128Rsa15`) | RSA PKCS#1 v1.5 padding oracle (CWE-204) | **Password recovery / account takeover** | 7.4 / **9.1 Critical** |
| RoleMapper dropped | `OpcUaServerConfig.copy()` | `RoleMapper` dropped → RBAC fails open (CWE-862) | Authorization bypass | 8.6 / 8.8 |
| Call mixed-batch | Call service | Mixed-batch authorization bypass (CWE-863) | Authorization bypass | 8.2 / 8.7 |
| Pre-auth memory leak | UASC transport | Pre-session direct-memory leak (CWE-401) | **Unauthenticated remote DoS (process-wide)** | 7.5 / 8.7 |
| Quota exhaustion | Subscriptions / decode | Monitored-item quota exhaustion + nested decode (CWE-460) | DoS | 7.5 / 6.9 |
| Diagnostics disclosure | Diagnostics nodes | Cross-session diagnostics disclosure (CWE-862) | Information disclosure | 6.4 / 6.9 |

**Working proof-of-concept code exists for the four strongest findings** — including the full
token-capture → password-recovery → impersonation chain — each with a Milo 1.1.5 negative control that is
the *same* PoC bytecode with only the Milo dependency changed. **The exploit code is withheld until
2026-07-30**, to give operators a short window to upgrade ahead of public PoCs. It will then be published
at `github.com/abhinavagarwal07/milo-security-poc`.

> **Affected:** Eclipse Milo server-side. Affected ranges vary by finding: **0.6.0–0.6.16 and/or
> 1.0.0–1.1.4**. See the per-finding ranges below. **All fixed in 1.1.5.**
{: .prompt-danger }

> **Disclosure:** Reported privately to the Eclipse Foundation Security Team on 2026-07-13; confirmed and
> fixed within days. The CVE IDs were reserved by the Eclipse Foundation (CNA) on 2026-07-16 and are
> pending publication. Coordinated with CERT/CC (**VU#813184**) given the ICS/OT surface.
> See [Disclosure status](#disclosure-status-fixed-in-public-cves-still-pending).
{: .prompt-info }

---

## Impact

OPC UA servers are not desktop software — a Milo server is typically the thing an OT client authenticates
to, reads process values from, and issues commands through. Here is what each class of finding gives an
attacker, and what I demonstrated versus what is deployment-dependent.

| Path | Demonstrated | Operational consequence (deployment-dependent) |
|------|--------------|--------------------------------------------------|
| Username-token padding oracle | Full plaintext password recovery from one captured token and login as that user, against a Milo server configured with `Basic128Rsa15` | Account takeover of an OPC UA user — read/write access to whatever that identity is authorized for |
| Pre-auth memory leak | Unauthenticated remote client drives the server to `OutOfMemoryError`; in a memory-limited deployment the **process is OOM-killed** | Loss of the OPC UA server and every co-located route/service in that JVM until restart |
| RBAC fails open / Call bypass | A lower-privileged/anonymous client invokes a role-protected method that should be denied | Unauthorized calls, writes, or node operations on servers that rely on role permissions |
| Diagnostics disclosure | An anonymous client enables diagnostics and enumerates other sessions | Leak of other users' session metadata; under trusted-cert configs, their usernames and certificates |

### The one that matters most: recovering OPC UA passwords

The username-token flaw is a textbook **Bleichenbacher padding oracle**. When a Milo server is configured to accept
`Basic128Rsa15` username tokens (RSA PKCS#1 v1.5), the identity validator returns *distinguishable* status
codes for the different ways a decrypt can fail — valid padding with a wrong password is reported
differently from invalid padding. That difference is an oracle: an on-path attacker who captures **one**
victim's encrypted username token can replay adaptively chosen ciphertexts and, one padding-validity bit
at a time, reconstruct the RSA plaintext — i.e. the password.

This is not theoretical. Against Milo 1.1.4 configured with a `Basic128Rsa15` username policy and a
2048-bit key, a recording relay captured a legitimate user's `ActivateSession` token off the wire, and the
recovery returned the **full plaintext password in 11,675 adaptive oracle queries — under 13 seconds**. A raw
`ActivateSession` with the recovered password then returned `Good`; with a wrong password,
`Bad_UserAccessDenied`. The fix in 1.1.5 collapses every failure mode to one uniform status, closing the
oracle. (Recovery is probabilistic per run, so query counts vary between runs on identical inputs.)

The preconditions are real and worth stating plainly: `Basic128Rsa15` is a deprecated policy an operator
must opt into, and the attacker needs an on-path capture of one token — which is exactly why the CVSS 4.0
vector carries `AT:P`. But where those hold, this is credential compromise, not a nuisance.

### The one that needs no credentials: an unauthenticated, process-wide crash

The memory leak needs nothing. Milo's UASC transport retains partial message chunks in pooled **off-heap
(direct) memory** and fails to release them when a channel disconnects. Because `SecurityPolicy.None` is
accepted for channel setup, an unauthenticated client can open a channel, send non-final chunks, drop the
connection, and repeat — permanently leaking direct memory that garbage collection never reclaims. There
is no session, no credential, and no user interaction.

In a memory-limited container the result is a hard denial of service: the JVM is **OOM-killed (exit 137)**
within seconds, and because a Milo server shares its JVM (and Netty's global direct-memory pool) with
everything else in that process, the kill takes down co-located services too — I confirmed a second,
independent route in the same host process dying with it.

---

## Disclosure status: fixed in public, CVEs still pending

The fixes for all six issues are already public — they shipped in Milo 1.1.5 on 2026-07-16, and the
individual fix commits describe each security problem plainly. The CVE IDs were reserved by the Eclipse
Foundation (CNA) that same day, but as of this writing they have **not been published**, and my requests
to publish them (2026-07-21 and 2026-07-22) went unanswered.

I am publishing because the preconditions for responsible disclosure are met: the Eclipse Milo project
cleared public disclosure of these findings on **2026-07-15**, the fix release has been public for over a
week, and a reserved-but-unpublished CVE warns no one while the public commits already spell out the bugs.
Given the ICS/OT surface, I notified CERT/CC (**VU#813184**) on 2026-07-26 of this upcoming advisory; if a
coordinating body elects to issue its own, that takes precedence.

## Timeline

| Date | Event |
|------|-------|
| 2026-07-13 | Reported privately to the Eclipse Foundation Security Team (six findings). |
| 2026-07-15 | Eclipse Milo project (maintainer) confirmed all findings; cleared public disclosure. |
| 2026-07-16 | Eclipse Milo **1.1.5** released with all fixes; CVE IDs reserved by the Eclipse Foundation (CNA). |
| 2026-07-17 | CERT/CC case opened (**VU#813184**). |
| 2026-07-21 | Requested CVE publication (again 2026-07-22); no response. |
| 2026-07-26 | CVE publication requests filed with Eclipse; CERT/CC notified of upcoming private advisory. |
| 2026-07-28 | This advisory. |
| 2026-07-30 | Proof-of-concept exploit code to be published. |

---

## Technical details

### `Basic128Rsa15` username-token padding oracle

**CVSS 3.1:** 7.4 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`) ·
**CVSS 4.0:** 9.1 Critical (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`) · CWE-204
{: .prompt-tip }

The `AC:H` in the v3.1 vector and the `AT:P` in the v4.0 vector both encode the same precondition: the
attacker must capture a victim's encrypted token, which the demonstrated method does from an on-path
position. This is not a no-prerequisites remote attack, and the scores say so.

Milo's identity-token decryption path maps the several failure modes of an RSA PKCS#1 v1.5 unpad to
*different* OPC UA status codes: a validly-padded block with the wrong password reaches a distinct
authentication-failure code, while a badly-padded block returns a security-check failure. That observable
discrepancy (CWE-204) is a decryption oracle over the `Basic128Rsa15` username token.

Concretely, against Milo ≤ 1.1.4:

```text
valid PKCS#1 padding + wrong password  ->  Bad_UserAccessDenied      (0x801F0000)
invalid PKCS#1 padding (random bytes)  ->  Bad_SecurityChecksFailed  (0x80130000)
```

Two different answers to "was the padding well-formed?" — which is all Bleichenbacher needs. On 1.1.5 both
cases return the same `Bad_IdentityTokenInvalid` (0x80200000), so the oracle bit is constant and the attack
gets no signal.

#### From oracle to plaintext password

The PoC (to be published on 2026-07-30) runs the full chain against Milo 1.1.4 configured with a `Basic128Rsa15` username policy:

1. **Discover and validate.** Connect, enumerate endpoints, confirm a `UserName` policy with
   `Basic128Rsa15`, and fetch the server certificate and its 2048-bit RSA public key. The certificate's
   SHA-256 fingerprint is recorded — the attack is bound to that key, not to a version string.
2. **Confirm the oracle.** Send the two probes above on an unauthenticated session. If the statuses are
   distinguishable, the oracle is live; if they are uniform (1.1.5), the PoC reports *not vulnerable* and
   refuses to attempt recovery. Timeouts, malformed replies, and rate-limiting count as **unknown** — never
   as "padding valid."
3. **Capture one victim token.** A recording relay sits in the victim's path and extracts the encrypted
   `UserNameIdentityToken.password` block (256 bytes for a 2048-bit key) out of a legitimate
   `ActivateSessionRequest`. That single ciphertext is the entire input to the attack.
4. **Recover.** The attacker opens **one anonymous session — no credentials of any kind** — and over it
   sends adaptive `ActivateSession` identity-change requests for the victim account, using each
   padding-validity answer to narrow the search space. Every decision comes from a real remote response;
   the attacker holds no private key and does no local decryption.
5. **Parse and prove.** Validate the recovered block structure
   (`00 02 || padding || 00 || little-endian length || password || server nonce`), then make two fresh
   authentication attempts: a deliberately wrong password → denied, and the **recovered** password →
   `Good`.

Against a full 2048-bit key the attack recovered the password in **11,675 wire oracle queries — 12.8
seconds**, and the recovered string authenticated as the victim. Cost varies substantially run to run:
Bleichenbacher's initial blinding search is geometrically distributed, so the *query count* itself swings
by roughly an order of magnitude between runs on identical inputs (a checkpoint/resume run took 24,922 queries across five
budget-limited attempts). What matters is not the exact count but that the server answers every one of those
queries — from an anonymous session, with no credentials for the victim account, and unthrottled.

**What makes this a proof rather than a demo:** the victim password is generated at **runtime**, and the
attacker process never receives it — not as an argument, an environment variable, a file, or a system
property. It gets only the target address, the captured ciphertext, the username, the policy id, and the
server certificate. A separate verifier compares the recovered value against the real one *after* the fact.
The attacker prints its answer without knowing whether it is right.

**Fix:** all failure modes return one uniform status
([commit `db59fae9`](https://github.com/eclipse-milo/milo/commit/db59fae993a3a1bc66fffc8a2796d444b40285fb),
PR #1804). **Affected:** 0.6.0–0.6.16 and 1.0.0–1.1.4.

> **Conditions.** The server must be configured to accept the **deprecated `Basic128Rsa15`** username-token
> policy — not a default — and the attacker needs an **on-path capture of one victim token**. Both are
> priced into the scores (`AC:H` in v3.1, `AT:P` in v4.0). Given those, no further privilege is required:
> the oracle queries carry no credentials for the victim account and are not rate-limited.
{: .prompt-warning }

### pre-authentication direct-memory leak

**CVSS 3.1:** 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) · **CVSS 4.0:** 8.7 High (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`) · CWE-401
{: .prompt-tip }

The UASC asymmetric handler holds incomplete inbound chunks in pooled direct buffers and only releases
them on `exceptionCaught`, not on `channelInactive`. A client that opens a `None` channel, sends a
non-final chunk, and disconnects leaks those buffers permanently.

#### The attack

The PoC attacker (to be published on 2026-07-30) is a **pure-socket client with no Milo or OPC UA library
dependency** — it speaks just enough UASC to open a `SecurityPolicy.None` channel, emit chunks with the final-chunk flag never set, and hang up.
Repeat. Each iteration strands buffers the server will never free. Two outcomes, depending on how the JVM
is bounded:

- **Bounded direct memory** (`-XX:MaxDirectMemorySize`): usage climbs to the cap and stays pinned; a forced
  `jcmd GC.run` reclaims none of it — proving a leak rather than transient allocation — and the server logs
  repeated `OutOfMemoryError: Cannot reserve … direct buffer memory` from `UascServerAsymmetricHandler`.
- **Container memory limit, no protective cap** (the common Docker/Kubernetes shape): the JVM is
  **OOM-killed — `OOMKilled=true`, `ExitCode 137`** — within seconds, and a legitimate client that connected
  and read successfully before the attack can no longer be served until the process is restarted.

The Milo 1.1.5 control runs the same attack harness, resource limits and runtime budget with only the Milo
dependency changed — and stays flat and alive under equal or greater load, so the only variable is the Milo
jar. Note the attacker is run from a separate
(non-loopback) network peer, so Milo's rate limiter, which exempts loopback, is genuinely in play.

**Fix:** release retained chunks on
teardown ([commit `45971579`](https://github.com/eclipse-milo/milo/commit/459715793ec54b0f33367a14f94264500a0d872b),
PR #1800). **Affected:** 0.6.0–0.6.16 and 1.0.0–1.1.4.

### `OpcUaServerConfig.copy()` drops `RoleMapper`

**CVSS 3.1:** 8.6 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L`) · **CVSS 4.0:** 8.8 High (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`) · CWE-862
{: .prompt-tip }

`OpcUaServerConfig.copy()` omits the configured `RoleMapper`. A server built from a copied config
therefore has no role mappings, so the access controller sees no roles and role-permission checks
silently pass — RBAC fails open (CWE-862). This bites any embedding that constructs its running config via
`copy()`. **Fix:** preserve the mapper on copy ([commit `d51f03e9`](https://github.com/eclipse-milo/milo/commit/d51f03e9a75f313ab41c3d68d809f4b922073f1a),
PR #1801). **Affected:** 1.0.0–1.1.4.

### Call service mixed-batch authorization bypass

**CVSS 3.1:** 8.2 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L`) · **CVSS 4.0:** 8.7 High (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`) · CWE-863
{: .prompt-tip }

The Call service computes which requested methods are authorized and which are denied, then dispatches the
**original, unfiltered** batch to the address-space handlers. A denied method batched alongside an allowed
one executes anyway (CWE-863) — so a low-privileged or anonymous client can invoke a method it should not.
**Fix:** dispatch only the authorized set ([commit `59b50bed`](https://github.com/eclipse-milo/milo/commit/59b50bed094de0d18a130a48f3527254dc76105d),
PR #1802). **Affected:** 1.0.0–1.1.4.

### cross-session diagnostics disclosure

**CVSS 3.1:** 6.4 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`) · **CVSS 4.0:** 6.9 Medium (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`) · CWE-862
{: .prompt-tip }

The server diagnostics `EnabledFlag` is writable by any session, and the session-diagnostics arrays are
readable without adequate authorization (CWE-862). An anonymous client over a `None`/`None` endpoint can
enable diagnostics and read other sessions' information; with a trusted client-application certificate this
extends to the session *security* diagnostics, which carry other users' names and certificates. **Fix:**
restrict diagnostics to an admin role ([commit `a5dae1be`](https://github.com/eclipse-milo/milo/commit/a5dae1be0657d2b4fcb66e63f377c1dc36069e2a),
PR #1803). **Affected:** 0.6.0–0.6.16 and 1.0.0–1.1.4.

### nested-decode / monitored-item quota exhaustion

**CVSS 3.1:** 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) · **CVSS 4.0:** 6.9 Medium (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`) · CWE-460
{: .prompt-tip }

Two related defects in the same area. First, nested `ExtensionObject` decoding resets the recursion-depth
counter, so a deeply nested structure (~700 KiB) triggers a `StackOverflowError`. Second, monitored-item
quota accounting is not exception-safe: when item creation throws, the server-global reservation is not
restored, so the finite quota drains permanently (CWE-460). **Fix:** bound recursive decoding
([commit `587e3566`](https://github.com/eclipse-milo/milo/commit/587e35669f519b2d7f6d850a5f86ee5a76c3a2c5),
PR #1806) and make quota accounting exception-safe
([commit `5f3f6da2`](https://github.com/eclipse-milo/milo/commit/5f3f6da2a5ea80682e1da7c58f7a1870b09d2b43),
PR #1807). **Affected:** nested decoding 1.0.0–1.1.4; monitored-item quota accounting 0.6.8–0.6.16 and
1.0.0–1.1.4.

---

## Downstream exposure

Because Milo is a library, the practical reach of these issues depends on how each embedding configures and
exposes it. Any application that embeds a Milo **server** built from an affected version inherits the
findings above to the extent its configuration reaches them: the pre-auth memory leak needs only a
network-reachable endpoint, while the authorization and username-token findings depend on whether RBAC and
a `Basic128Rsa15` username policy are in play.

I identified downstream projects that embed affected Milo versions and **confirmed exploitability against
at least one of them end-to-end**, with a same-bytecode control that swapped only the Milo jar to 1.1.5.
Those projects have been notified directly. **Per-project details are withheld for now**, at the
maintainers' request, and are not published here.

If you ship or operate software that embeds Milo, check the version you pin and move to 1.1.5.

## Reproducing

> **The exploit code is withheld until 2026-07-30.** The repository below goes live on that date; the
> commands are shown now so operators can plan their testing. Upgrade first.
{: .prompt-warning }

Each PoC is a self-contained Maven project that builds against the **released** Milo artifacts from Maven
Central — no Milo source tree needed — and each ships a Milo 1.1.5 negative control that is the *same* PoC
bytecode with only the dependency changed. Run them in a disposable VM.

```bash
git clone https://github.com/abhinavagarwal07/milo-security-poc && cd milo-security-poc

# Padding oracle — capture a victim token, recover the plaintext password, impersonate
( cd username-token-padding-oracle/poc && ./run.sh )

# Memory leak — unauthenticated pre-session leak; container run ends in OOM-kill (exit 137)
( cd uasc-preauth-memory-leak/poc && ./run.sh )

# The two authorization bypasses — a denied method executes anyway
( cd serverconfig-copy-rolemapper/poc && ./run.sh )
( cd call-mixed-batch-authz-bypass/poc && ./run.sh )

# Each PoC includes a Milo 1.1.5 negative control.
# See its README for the exact command.
```

---

## Mitigation

- **Upgrade to Eclipse Milo 1.1.5.** For embeddings, bump the transitive Milo dependency; for the 0.6.x
  line there is no fixed 0.6 release, so remediation is a 0.6 → 1.x migration.
- **Interim, for the pre-auth DoS:** firewall the OPC UA port to trusted hosts; avoid exposing
  `SecurityPolicy.None`; set a bounded `-XX:MaxDirectMemorySize` so the leak degrades to allocation
  failures rather than an outright process kill; add connection limits/idle timeouts.
- **For the padding oracle:** stop offering the deprecated `Basic128Rsa15` username policy.
- **For RBAC:** if you build your running config via `OpcUaServerConfig.copy()`, verify `getRoleMapper()`
  is present at startup until upgraded.

## References

- **PoC artifacts** (available from 2026-07-30): `github.com/abhinavagarwal07/milo-security-poc`
- Eclipse Milo 1.1.5 release: <https://github.com/eclipse-milo/milo/releases/tag/v1.1.5>
- Eclipse tracking issue: <https://gitlab.eclipse.org/security/vulnerability-reports/-/work_items/598>
- CERT/CC: VU#813184
- [CWE-204](https://cwe.mitre.org/data/definitions/204.html) ·
  [CWE-401](https://cwe.mitre.org/data/definitions/401.html) ·
  [CWE-862](https://cwe.mitre.org/data/definitions/862.html) ·
  [CWE-863](https://cwe.mitre.org/data/definitions/863.html) ·
  [CWE-460](https://cwe.mitre.org/data/definitions/460.html)
- Library: [eclipse-milo/milo](https://github.com/eclipse-milo/milo)
- CVE IDs have been reserved by the Eclipse Foundation (CNA) but are not yet published. Per the CNA's
  terms, reserved identifiers are not cited here; this page will be updated once they are public.
