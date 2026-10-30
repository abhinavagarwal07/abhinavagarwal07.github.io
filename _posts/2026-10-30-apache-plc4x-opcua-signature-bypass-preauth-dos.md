---
layout: post
title: "An Inverted If and a Stale Length: Apache PLC4X's OPC UA Client Accepted Forged Secure-Channel Signatures"
date: 2026-10-30 00:00:00 +0000
categories: [Security, Advisory]
tags: [apache-plc4x, opc-ua, iec-62541, ics, ot, industrial-iot, mitm, signature-bypass, certificate-validation, denial-of-service, cwe-347, cwe-295, cwe-757, cwe-789, cwe-770]
description: "Apache PLC4X's OPC UA client checked OPN signatures with an inverted branch over a misaligned byte range, and by default trusted whatever certificate discovery returned. An impersonating server could capture credentials and rewrite writes. Plus three pre-authentication allocation bugs. CVE-2026-102508 (9.2) and CVE-2026-102509 (8.7), fixed in 1.0.0."
toc: true
---

## Summary

[Apache PLC4X](https://plc4x.apache.org/) is a universal protocol adapter for industrial
communication — one API over OPC UA, Modbus, S7, EtherNet/IP, ADS, KNX and others. It is a
**client-side** library: the component inside a SCADA bridge, historian feeder or IIoT gateway that
talks to PLCs and OPC UA servers.

I reported four defects in the Java implementation (PLC4J) on 2026-07-09. They were published as
two CVEs:

| CVE | Title | CVSS 4.0 | CWE | Affected |
|---|---|---|---|---|
| [CVE-2026-102508](https://www.cve.org/CVERecord?id=CVE-2026-102508) | OPC UA secure channel: integrity bypass, unverifiable server certificate, and silent downgrade | **9.2 Critical** | CWE-347, CWE-295, CWE-757 | 0.9.0 – 0.13.1 |
| [CVE-2026-102509](https://www.cve.org/CVERecord?id=CVE-2026-102509) | Pre-authentication resource exhaustion in the OPC UA driver and the Java SPI parser | **8.7 High** | CWE-789, CWE-770, CWE-674 | 0.10.0 – 0.13.1 |

> **Fixed in PLC4X 1.0.0** (2026-09-07). There is no fixed 0.13.x release.
{: .prompt-danger }

Two independent bugs in the asymmetric receive path compose so that the client accepts exactly those
`OPN` chunks whose signature **fails** to validate — and a correctly computed signature is among
those that fail. Separately, the client by default trusted whichever certificate discovery handed
it. Together: an impersonating server reads the user's password and rewrites channel traffic, and
never needs a valid signature.

---

## Impact

PLC4X is a client, so the attacker is a malicious or impersonated **server** — a rogue endpoint, a
compromised device, or a relay on the path.

| Path | Consequence |
|---|---|
| Server impersonation | With no trust anchor (the default), the client encrypts its nonce and the user's OPC UA password to the attacker's certificate. The attacker derives the channel keys, then reads and rewrites traffic with no error at the client. |
| Pre-authentication DoS | Loss of the client's OPC UA function during secure-channel and session setup, before user authentication. |

---

## CVE-2026-102508 — a check that accepted signatures which failed validation

### Bug 1: the branch sense is inverted (0.12.0 – 0.13.1)

`AsymmetricEncryptionHandler.verify()`, at v0.13.1
[lines 41–52](https://github.com/apache/plc4x/blob/v0.13.1/plc4j/drivers/opcua/src/main/java/org/apache/plc4x/java/opcua/context/AsymmetricEncryptionHandler.java#L41-L52):

```java
Signature signature = securityPolicy.getAsymmetricSignatureAlgorithm().getSignature();
signature.initVerify(conversation.getRemoteCertificate().getPublicKey());
signature.update(message);
if (signature.verify(signatureData)) {          // <-- missing negation
    throw new IllegalArgumentException("Invalid signature");
}
```

`verify()` returning `true` means the signature is good. The method throws on `true` and returns
normally on `false`: a signature that validates raises "Invalid signature", and one that does not
is accepted.

### Bug 2: the checked bytes are misaligned

`BaseEncryptionHandler.decodeMessage()` decrypts the chunk first and verifies it second, but hands
`verify()` the *original on-the-wire* length:

```java
int bodySize = messageLength - chunk.getSecurityHeaderSize() - SECURE_MESSAGE_HEADER_SIZE;
if (chunk.isEncrypted()) {
    bodySize = decrypt(chunkBuffer, chunk, messageLength);   // returns the post-decrypt size
}
if (chunk.isSigned()) {
    verify(chunkBuffer, chunk, messageLength);               // ...which is discarded here
}
```

Under `Basic256Sha256` the asymmetric algorithm is `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`, so with a
2048-bit key each 256-byte ciphertext block decrypts to at most 214 bytes (OAEP overhead
`2 * hLen + 2` = 42). The buffer shrinks 42 bytes per RSA block — 84 bytes for the two-block `OPN`
response I used. Since `verify()` computes

```java
int signatureStart = messageLength - chunk.getSignatureSize();
```

the slice it treats as the signature sits that far past the real one: the tail of the real
signature followed by stale bytes left over from decryption.

### How they compose

Bug 2 normally hands `verify()` bytes that will not validate, so it returns `false`. Bug 1 treats
`false` as success. Zeros, random bytes and a correctly computed signature are all accepted; the
one input rejected is a signature crafted to validate over the misaligned range.

Fixing only the inverted branch is not enough: with the stale length still in place, legitimate
encrypted-and-signed `OPN` responses would be rejected.

### Scope of the bypass

`EncryptionHandler.decodeMessage()` routes only `OpcuaOpenResponse` and `OpcuaOpenRequest` through
the asymmetric handler. `MSG`/`CLO` chunks go through `SymmetricEncryptionHandler`, whose HMAC
comparison is fail-closed:

```java
if (!MessageDigest.isEqual(signatureData, signatureBytes)) {
    throw new IllegalArgumentException("Invalid signature");
}
```

So the bypass covers `OPN` only, and on its own it does not give an on-path attacker the channel
keys: they derive from a client nonce that the client encrypts to whichever server certificate it
trusts. The certificate default closes that gap.

### No trust anchor was required

`OpcuaDriverContext` fell back to a **permissive** certificate verifier when no `trust-store-file`
was configured, and took the server certificate from the **unauthenticated `GetEndpoints`
response** (`discovery=true` is the default). That certificate encrypts the `OPN` request — client
nonce included — and the user's password. An attacker that supplies it holds the matching private
key, so it could sign `OPN` correctly; because of the bugs above, it need not.

### Policy-selection downgrade

The default `security-policy` is `None` in every affected version. From 0.12.0, endpoint filtering in
`SecureChannel` skips a candidate only when the policy **and** the message-security mode both
mismatch:

```java
boolean policyMatch = endpointDescription.getSecurityPolicyUri().getStringValue()
    .equals(securityPolicy.getSecurityPolicyUri());
boolean msgSecurityMatch = endpointDescription.getSecurityMode().equals(effectiveMessageSecurity);

if (!policyMatch && !msgSecurityMatch) {
    continue;
}
```

An endpoint whose mode matches is therefore admitted even when its policy is weaker than the
configured one. From 0.13.0 the admitted candidates are sorted by ascending `securityLevel`, so the
lowest-security survivor is preferred (CWE-757).

### The 0.9.0 – 0.11.0 variant

Older releases fail differently. In `EncryptionHandler.java` at v0.11.0, a failed check is logged
at `INFO` and parsing continues:

```java
if (!checkSignature(getBytes(buf.getBytes(), 0, tempPos))) {
    LOGGER.info("Signature verification failed: - {}", ...);   // no throw, no return
}
```

`checkSignature()` is itself wrong — it digests the whole buffer, signature included, then reads
the expected signature from the **start** of the buffer rather than the end:

```java
signature.update(data);
return signature.verify(data, 0, data.length - 256);
```

There is no trust-anchor mechanism in that range.

### Reconstructing it

Client: `security-policy=Basic256Sha256`, `SignAndEncrypt`, default `discovery=true`, no
`trust-store-file` — the strongest policy and mode, without a trust store. A relay on the path:

1. answers `GetEndpoints` with endpoint descriptions carrying its own certificate;
2. receives the `OPN` request encrypted to that certificate, decrypts it, and reads the client
   nonce;
3. answers `OPN` with its own server nonce, encrypted to the client certificate from the request,
   under a signature that need not validate;
4. derives the symmetric keys from the two nonces, and from then on reads and authors correctly
   MACed `MSG` traffic — including `ActivateSession`, whose password is encrypted to the relay's
   certificate.

In my testing (2048-bit keys) this captured the test credentials and changed a write from `100.0`
to `999.0`; an independent observer on the server-side subnet confirmed the modified value reached
the real server, and the client reported no error. The client was pointed directly at the relay,
and the relay's upstream leg used `SecurityPolicy.None`.

---

## CVE-2026-102509 — three pre-authentication allocation bugs

The byte-string and chunk cases were driven over a socket; the array-count case was reproduced at
parser level, with its network route traced in source. The published CVE also covers two defects
found during remediation — collections pre-sized from server-supplied element counts, and recursive
`mspec` types parsed without a depth limit (the Go counterpart of the latter is
[CVE-2026-102510](https://www.cve.org/CVERecord?id=CVE-2026-102510)).

### Length-prefixed byte strings (0.10.0 – 0.13.1)

`PascalByteString.staticParse()` reads a **signed** 32-bit length off the wire and passes it
through, special-casing only `-1`:

```java
int stringLength = readSimpleField("stringLength", readSignedInt(readBuffer, 32));
byte[] stringValue = readBuffer.readByteArray(
    "stringValue", Math.toIntExact((((stringLength) == (-(1))) ? 0 : stringLength)));
```

and `ReadBufferByteBased.readByteArray()` allocates before checking the bytes exist:

```java
bitPos += numberOfBytes * 8;
byte[] bytes = new byte[numberOfBytes];     // allocate first, read second
for (int i = 0; i < numberOfBytes; i++) {
    bytes[i] = readByte();
}
```

**Trigger.** Complete `HEL`/`ACK`, receive the client's `OPN`, then answer with an 88-byte `OPNF`
response: the 12-byte message header (`OPN` + `F` + 4-byte size + 4-byte secure channel id), then
the asymmetric security header — `securityPolicyUri` as a `PascalString`, `senderCertificate` and
`receiverCertificateThumbprint` as `PascalByteString`s. Set `senderCertificate.stringLength` to
`FF FF FF 7F` (`0x7FFFFFFF` little-endian): bytes 63–66 with the 47-byte `SecurityPolicy#None` URI,
or from byte 73 with `Basic256Sha256`. The client reaches `new byte[2147483647]`. This header is
parsed before any certificate or signature check, so the client's trust configuration does not
matter.

### Array counts in generated parsers (0.10.0 – 0.13.1)

`FieldReaderArray.readFieldCount()` bounds the count only against `Integer.MAX_VALUE`, then uses it
as an `ArrayList` initial capacity:

```java
if (count > Integer.MAX_VALUE) {
    throw new ParseException("Array count of " + count + " exceeds the maximum allowed count ...");
}
if (count < 0) {
    return null;
}
int itemCount = Math.max(0, (int) count);
List<T> result = new ArrayList<>(itemCount);    // eager backing array
```

The backing `Object[]` is allocated before a single element is read. Exactly `0x7FFFFFFF` exceeds
HotSpot's maximum array length and fails fast with `OutOfMemoryError: Requested array size exceeds
VM limit`; somewhat smaller counts make a genuine multi-gigabyte allocation attempt.

**Triggers.** At parser level, the OPC UA `Variant` prefix `86 FF FF FF 7F` — encoding byte `0x86`
is builtin type 6 (`Int32`) with the array bit `0x80` set, followed by the int32 count. Over the
wire, the fields are `noOfServerEndpoints` and `noOfServerSoftwareCertificates` in
`CreateSessionResponse`, read through `readCountArrayField()` and parsed in `SecureChannel` before
`ActivateSession` is sent, behind valid `MSG`, `ExtensionObject` and `ResponseHeader` framing.

### Chunk accumulation without limits (0.12.0 – 0.13.1)

`Conversation` negotiates and stores `maxChunkCount` and `maxMessageSize`, then never consults them
on the inbound path:

```java
private boolean accumulateChunkUntilFinal(ChunkStorage storage, ChunkType chunkType, Payload data) {
    if (ABORT.equals(chunkType)) {
        storage.reset();
        return true;
    }
    if (!(data instanceof BinaryPayload)) {
        throw new IllegalArgumentException("Unexpected payload type " + data.getClass());
    }
    storage.append(((BinaryPayload) data).getPayload());   // no count or size check
    return FINAL.equals(chunkType);
}
```

**Trigger.** Complete `HEL`/`ACK` and `OPN`, wait for the client's `CreateSessionRequest`, then
stream `MSG` chunks flagged `C` (continue) with the expected secure-channel and token identifiers
and increasing sequence numbers, never sending `F` (final). Chunks accumulate in
`MemoryChunkStorage` indefinitely. I used 2,000 chunks of 61,440 payload bytes, roughly 120 MB.

Accumulation runs after each chunk is decoded, so this and the `CreateSessionResponse` route pass
through the channel's symmetric check: under the default `None` policy that needs no keys; under a
secure policy the sender must be a server the client accepted.

### Observed effect

Loss of the client's OPC UA function rather than process termination. The byte-string case threw
`OutOfMemoryError` repeatedly on the Netty thread while the client retried; the chunk case exited
the JVM only with the non-default `-XX:+ExitOnOutOfMemoryError`, and hung without it.

---

## Fixes

| Commit | Date | What it changed |
|---|---|---|
| [`a2dbb6bfc0`](https://github.com/apache/plc4x/commit/a2dbb6bfc0ef0060674d5614d99f32da0c749795) | 2026-07-10 | OPC UA driver: negation restored in `verify()`; post-decrypt length passed to `verify()`; default certificate verifier changed to fail-closed |
| [`5a4d5bdb4c`](https://github.com/apache/plc4x/commit/5a4d5bdb4c1b0e9356eff00af198bdb6aa960f26) | 2026-07-10 | Chunk-count and message-size limits enforced on accumulation; array initial capacity capped at 1024 |
| [`372501287d`](https://github.com/apache/plc4x/commit/372501287d088572ff7ac35364fcc7d5f325fea5) | 2026-06-12 | New SPI; the rewritten read buffer calls `ensureAvailable()` before allocating |

The read-buffer change came from an SPI rewrite that predates the report but had not shipped:
0.13.1 was affected. The signature fix in 1.0.0 addresses both halves:

```java
// AsymmetricEncryptionHandler — negation restored
if (!signature.verify(signatureData)) {
    throw new IllegalArgumentException("Invalid signature");
}

// BaseEncryptionHandler — verify against the post-decryption length
int decryptedMessageLength = SECURE_MESSAGE_HEADER_SIZE + chunk.getSecurityHeaderSize() + bodySize;
verify(chunkBytes, chunk, decryptedMessageLength);
```

1.0.0 also defaults to `Basic256Sha256` with `SignAndEncrypt`, fails closed on an unverifiable
server certificate unless verification is explicitly disabled with `tls.verify=false`, and fails the
connection if the negotiated policy is weaker than the one configured. I verified all four fixes
against `v1.0.0` and current `develop`.

## Downstream exposure

PLC4X is a library, so exposure follows the downstream pin — and almost every PLC4J consumer I
checked is still on a pre-1.0.0 one. CVE-2026-102508 needs `plc4j-driver-opcua`, which
`plc4j-driver-all` pulls in. CVE-2026-102509's SPI defects ship with every driver, but what a
device can make the parser allocate depends on the protocol's field widths: OPC UA and ADS use
32-bit lengths and counts; Modbus and S7 use 8- and 16-bit ones, which keeps each allocation well
under a megabyte.

| Downstream | PLC4X pin | Exposure |
|---|---|---|
| Apache Camel `camel-plc4x` — 4.23.0 (latest), LTS 4.22.2 and 4.18.5 | 0.13.1 | Both (bundles the OPC UA driver) |
| Camel `camel-plc4x` 4.14.9 (LTS) / 4.10.0 / 4.8.0 | 0.13.0 / 0.12.0 | Both |
| Camel Spring Boot starter, Camel Karaf | inherited (0.13.1) | Both |
| PLC4X's own integrations on the old `org.apache.plc4x` coordinates — NiFi NARs, Kafka Connect, Calcite, `plc4x-opcua-server` (last published 2025-09-02) | 0.13.1 | Both, via `plc4j-driver-all` |
| Apache StreamPipes 0.98.0 | 0.13.1 | SPI only — `plc4j-driver-all` with `plc4j-driver-opcua` excluded; its OPC UA adapter uses Eclipse Milo |
| Apache HertzBeat 1.8.0 / 1.9.0 | 0.12.0 | SPI only (Modbus and S7 drivers) |

Camel's `main` has moved to PLC4X 1.0.0 (CAMEL-25617, merged 2026-10-27) but not released it. The
PLC4X integrations are republished under `org.apache.plc4x.extras` at 1.0.0; the old coordinates
are the stale ones, and there it is the NiFi NARs that ship the OPC UA driver — the processor jars
reference it only at `test` scope. Roughly a dozen smaller open-source OT gateways and PLC bridges
pin 0.9.0 – 0.13.1; `json-scada` is already on 1.0.0. openHAB, Apache NiFi, Apache IoTDB, Eclipse
Ditto and Node-RED do not depend on PLC4X.

**What this buys an attacker.** Camel is the case that matters: `camel-plc4x` typically bridges an
OT network into enterprise systems, and it ships the OPC UA driver. Against a Camel route reading
from an OPC UA endpoint, a rogue or impersonated server can harvest the OPC UA credentials
configured in the route, alter the process values it carries — so falsified data lands in the
historian, database or Kafka topic downstream with no error at the Camel end — and stall the route
during connection setup. The same applies to PLC4X's own NiFi and Kafka Connect integrations.

StreamPipes and HertzBeat carry the vulnerable SPI without the OPC UA driver. HertzBeat's Modbus
and S7 collectors are bounded by those protocols' field widths. StreamPipes ships the rest of
`plc4j-driver-all`, ADS included, so its exposure depends on which adapters are in use.

## Mitigation

- **Upgrade to PLC4X 1.0.0.** There is no fixed 0.13.x release, so on the 0.x line this is a
  migration.
- Until then, configure a `trust-store-file`: in my testing it blocked the attacker certificate and
  nothing was captured. It leaves the `OPN` check broken and does not stop the byte-string trigger,
  which precedes any certificate check. Set an explicit non-`None` `security-policy`, and restrict
  which hosts the client can reach.

## Timeline

| Date | Event |
|---|---|
| 2026-07-09 | Four findings reported to `security@apache.org`. |
| 2026-07-10 | Apache routed the report to the PLC4X team; fixes committed to `develop` the same day. |
| 2026-07-25 | CERT/CC case opened (**VU#108987**). |
| 2026-09-07 | PLC4X **1.0.0** released with the fixes. |
| 2026-09-30 | ASF published CVE-2026-102508 and CVE-2026-102509. |
| 2026-10-30 | This write-up. |

## References

- ASF advisory page: <https://security.apache.org/projects/plc4x/>
- CVE-2026-102508 announcement: <https://www.openwall.com/lists/oss-security/2026/09/30/4>
- CVE-2026-102509 announcement: <https://www.openwall.com/lists/oss-security/2026/09/30/5>
- CERT/CC: VU#108987
- Project: [apache/plc4x](https://github.com/apache/plc4x)
