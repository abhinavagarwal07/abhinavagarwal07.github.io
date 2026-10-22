---
layout: post
title: "Four Authorization and Availability Findings in HAPI FHIR"
date: 2026-10-22 00:00:00 +0000
categories: [Security, Advisory]
tags: [hapi-fhir, fhir, hl7, healthcare, smile-cdr, authorization, denial-of-service, cwe-862, cwe-863, cwe-409]
description: "A transaction-bundle extension that overrides a trusted tenant partition, a conditional create that returns a resource the caller cannot read, subscription delivery detached from the creator's read scope, and unbounded inbound gzip decompression before authorization. Tested on HAPI FHIR 8.10.0."
toc: true
---

## Summary

[HAPI FHIR](https://github.com/hapifhir/hapi-fhir) is a widely used open-source Java implementation of HL7 FHIR. It underlies [Smile CDR](https://smilecdr.com) — whose changelog states "Smile CDR 2026.05.R01 is based on HAPI FHIR 8.10.0" — and many other products.

I reported four findings against **HAPI FHIR 8.10.0**, commit [`96ac50f89455`](https://github.com/hapifhir/hapi-fhir/commit/96ac50f89455eb4cbef57fa858854e58b6dac4a5), coordinated through CERT/CC as **VU#394579**.

| Finding | Demonstrated | CWE | CVSS 3.1 |
|---|---|---|---|
| Tenant partition override | A transaction-entry extension replaces a trusted gateway's partition header; foreign-partition reads, and a resource created in a foreign partition | 863 | 8.1 High |
| Inbound gzip decompression | Body inflated without a size cap, before HAPI's authorization hook | 409 | 7.5 High |
| Conditional-create disclosure | A predicate matching one resource returns its full representation to a caller denied a direct read | 863 | 4.3 Medium |
| Subscription delivery scope | A matching clinical resource reaches the subscriber's endpoint despite a denied direct read | 862 | 3.1 Low |

Scores are the assigned CVSS v3.1 values from the CISA draft of 2026-10-06. CVE identifiers are assigned through the CISA advisory and will be listed here once it is published.

Archived Surefire reports record 23 passing tests across seven classes on OpenJDK 17.0.19. I did not demonstrate code execution or authentication bypass. Line numbers refer to `96ac50f89455` unless stated.

> **Version scope:** tested on 8.10.0; source inspection found all four paths in v8.8.2, v8.10.1 and v8.12.1. The partition extension first shipped in v8.2.0 (`85abdc23007`). One fix exists in unreleased code only — see [Fix status](#fix-status).
{: .prompt-danger }

| Finding | Module | Prerequisites |
|---|---|---|
| Partition override | `hapi-fhir-storage` (JPA) | Partitioning; header-based tenant routing; caller can submit transaction or batch bundles; no `STORAGE_PARTITION_SELECTED` entitlement policy |
| Gzip decompression | `hapi-fhir-server` | Inbound decompression (default on); a reachable body-consuming operation |
| Conditional create | `hapi-fhir-server`, `hapi-fhir-storage` | CREATE without READ on the target type; `AuthorizationInterceptor` |
| Subscription delivery | `hapi-fhir-jpaserver-subscription` | REST-hook subscriptions (default off); Subscription-create grant |

## 1. Transaction bundle entry overrides a trusted tenant partition

**8.1 High** · `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` · CWE-863

In the tested topology, a trusted gateway authenticates the caller, strips any caller-supplied partition header, and writes the caller's tenant into `X-Request-Partition-IDs`. `RequestHeaderPartitionInterceptor` selects the partition from it.

[`BaseTransactionProcessor.setRequestPartitionHeaderIfEntryHasTheExtension()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-storage/src/main/java/ca/uhn/fhir/jpa/dao/BaseTransactionProcessor.java#L782-L790) (782-790; line 811 on master `f2fce24162a`) reads the extension `http://hapifhir.io/fhir/ns/StructureDefinition/request-partition-ids` from any `Bundle.entry.request`. Its string value names another partition. The handler passes it to [`ServletSubRequestDetails.setHeaders()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-server/src/main/java/ca/uhn/fhir/rest/server/servlet/ServletSubRequestDetails.java#L106-L109), which does `removeAll` then `putAll` on the sub-request's headers. Nothing authorizes the replacement.

The value reaches [`BaseRequestPartitionHelperSvc.validateAndNormalizePartition()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-storage/src/main/java/ca/uhn/fhir/jpa/partition/BaseRequestPartitionHelperSvc.java#L377) (377). For typed resource operations, in both named and unnamed mode, it calls `validateHasPartitionPermissions()` at 394, which broadcasts `STORAGE_PARTITION_SELECTED` at 420. A registered hook could check entitlement there. HAPI ships none, and the tested configuration had none.

**Evidence** — three classes, six tests, unnamed-partition mode:

- `C16PartitionReadBypassPocTest` (2/2), over HTTP. A caller with partition 1 in its gateway header sends a transaction whose GET entry carries the extension for another partition, and receives that partition's Patient. A `type=batch` Bundle with three GET entries reaches three partitions in one request.
- `C16PartitionBypassPocTest` (1/1), through `mySystemDao.transaction()`. An entry carrying the extension creates a Patient in a foreign partition.
- `C16PartitionEntitlementHookTest` (3/3), control. A `STORAGE_PARTITION_SELECTED` interceptor rejects the foreign write and permits an entitled one.

Writes were demonstrated as creation only; altering or deleting an existing foreign resource was not tested.

## 2. Unbounded inbound gzip decompression before authorization

**7.5 High** · `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` · CWE-409

[`RestfulServer.java:170`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-server/src/main/java/ca/uhn/fhir/rest/server/RestfulServer.java#L170) defaults `myUncompressIncomingContents` to `true`. With `Content-Encoding: gzip`, [`ServletRequestDetails.getByteStreamRequestContents()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-server/src/main/java/ca/uhn/fhir/rest/server/servlet/ServletRequestDetails.java#L98-L120) (98-120) reads the body into memory, then drains a `GZIPInputStream` through `IOUtils.toByteArray()` into a second `byte[]`. There is no size or ratio cap.

This happens before authorization. [`BaseOutcomeReturningMethodBinding.invokeServer()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-server/src/main/java/ca/uhn/fhir/rest/server/method/BaseOutcomeReturningMethodBinding.java#L166-L174) builds parameters at 166 and calls `invokeServerMethod()` at 174, which fires `SERVER_INCOMING_REQUEST_PRE_HANDLED` — `AuthorizationInterceptor`'s hook — at [`BaseMethodBinding.java:258`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-server/src/main/java/ca/uhn/fhir/rest/server/method/BaseMethodBinding.java#L258).

**Evidence:**

- `ServletRequestDetailsTest` (11/11). A 65,250-byte body expands to 67,108,864 bytes, 1,028:1.
- `ServletRequestDetailsGzipBombOomTest` (1/1). A forked `-Xmx64m` JVM calls the production routine via `loadRequestContents()` with a `MockHttpServletRequest`. A ~255 KB body targeting 256 MiB raises `OutOfMemoryError`; the harness catches it and halts the child itself. The same body through a 16 MiB-capped read completes.

This shows unbounded heap allocation in the pre-authorization path. The harness calls the routine directly rather than a running server, so **service availability was not measured.** A compressed-size cap alone does not give a reliable decompressed-size limit.

## 3. Conditional create returns a resource the caller cannot read

**4.3 Medium** · `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` · CWE-863

[`MatchResourceUrlService.processMatchUrl()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-storage/src/main/java/ca/uhn/fhir/jpa/dao/MatchResourceUrlService.java#L104) (104) resolves the conditional URL and, via `invokePreShowInterceptorForMatchUrlResults()` (197), broadcasts `STORAGE_PRESHOW_RESOURCES` on the match (202-219).

`AuthorizationInterceptor` handles that pointcut in [`hookPreShow()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-server/src/main/java/ca/uhn/fhir/rest/server/interceptor/auth/AuthorizationInterceptor.java#L443-L449) (443), so the hook fires. It calls [`checkOutgoingResourceAndFailIfDeny()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-server/src/main/java/ca/uhn/fhir/rest/server/interceptor/auth/AuthorizationInterceptor.java#L514-L521) (514), which returns at 517-521 without evaluating rules when the direction is `IN` or `NONE`. `determineOperationDirection()` (268) maps CREATE, UPDATE and PATCH to `IN` (291-294), and DELETE likewise (288-289).

On a single match, [`BaseHapiFhirResourceDao.doCreateForPostOrPut()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-jpaserver-base/src/main/java/ca/uhn/fhir/jpa/dao/BaseHapiFhirResourceDao.java#L597-L599) returns the stored entity with `setCreated(false).setNop(true)` (597-599), and the default `Prefer: return=representation` returns its body.

HAPI's 5.6.0 changelog ([`3047-inline-match-security.yaml`](https://github.com/hapifhir/hapi-fhir/blob/master/hapi-fhir-docs/src/main/resources/ca/uhn/hapi/fhir/changelog/5_6_0/3047-inline-match-security.yaml)) states that inline match URL searches receive the same access-control checks as other searches. This path skips the outgoing check on the matched resource.

**Evidence:** `AuthorizationInterceptorConditionalCreateReadBypassR4Test` (4/4). The caller holds Patient CREATE only; a direct `GET` of the target returns 403. A `POST /Patient` with an `If-None-Exist` predicate matching exactly one resource returns HTTP 200 with that Patient's full stored representation. The caller supplies the predicate; enumerating or discovering arbitrary records was not demonstrated.

**Upstream:** fixed in unreleased commit `063b073e8c1` (2026-08-19, PR [#8254](https://github.com/hapifhir/hapi-fhir/pull/8254)), after issue [#8253](https://github.com/hapifhir/hapi-fhir/issues/8253) (2026-08-13). The REST binding now suppresses the body whenever CREATE returns `created == FALSE`, and PATCH moves from `IN` to `BOTH`. CREATE still takes the `IN` early return; the fix suppresses the representation rather than adding a read check. Upstream's test confirms the matched resource's id still returns in `Location`. By inspection only, version metadata may remain in headers depending on configuration, and 200 versus 201 distinguishes match from no match.

## 4. Subscription delivery is not scoped to the creator's read access

**3.1 Low** · `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` · CWE-862

At creation, [`SubscriptionValidatingInterceptor.validateSubmittedSubscription()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-jpaserver-subscription/src/main/java/ca/uhn/fhir/jpa/subscription/submit/interceptor/SubscriptionValidatingInterceptor.java#L118-L194) (118-194) checks status, channel and matching strategy, and `validateCriteria()` (196) checks the criteria. [`validatePermissions()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-jpaserver-subscription/src/main/java/ca/uhn/fhir/jpa/subscription/submit/interceptor/SubscriptionValidatingInterceptor.java#L242-L271) (242-271) enforces only the cross-partition rules. None applies the creator's read policy, so criteria such as `Observation?` are accepted.

At delivery, [`SubscriptionDeliveringRestHookListener.getResource()`](https://github.com/hapifhir/hapi-fhir/blob/96ac50f89455eb4cbef57fa858854e58b6dac4a5/hapi-fhir-jpaserver-subscription/src/main/java/ca/uhn/fhir/jpa/subscription/match/deliver/resthook/SubscriptionDeliveringRestHookListener.java#L176-L182) (176-182) reloads the resource as `SystemRequestDetails` (179), a full-privilege internal identity. Neither matcher carries the creator's identity, and `AuthorizationInterceptor`'s request hook does not run for in-process delivery.

[FHIR R4](https://hl7.org/fhir/R4/subscription.html) states that criteria are subject to the same access limitations as the client that created the Subscription.

**Evidence:** `SubscriptionCreatorContextLossR4Test` (1/1), through the rest-hook pipeline. A deny-by-default `AuthorizationInterceptor` grants the principal only Subscription create and reads in Patient A's compartment. The principal subscribes to `Observation?status=final` with a full JSON payload to its own endpoint. An Observation then created in Patient B's compartment, same partition, carrying a synthetic marker, arrives at the endpoint in full. The principal's direct `GET` of it returns 403; a permitted `GET` returns 200.

The disclosure is one newly created `Observation`, not Patient B's chart. It crosses patient compartments within one partition and is **not** cross-tenant.

## Verification runs

Six of the seven classes were written for this research and are not in `96ac50f89455`; the gzip inflation case was added to the existing `ServletRequestDetailsTest`. Sources are withheld until the condition under [Disclosure](#disclosure) is met.

```bash
mvn test -pl hapi-fhir-server \
  -Dtest='ServletRequestDetailsTest,ServletRequestDetailsGzipBombOomTest'
mvn test -pl hapi-fhir-jpaserver-test-r4 \
  -Dtest='C16PartitionBypassPocTest,C16PartitionReadBypassPocTest,C16PartitionEntitlementHookTest,AuthorizationInterceptorConditionalCreateReadBypassR4Test,SubscriptionCreatorContextLossR4Test'
```

All data was synthetic. No production system, hospital, payer or commercial deployment was tested.

## Downstream footprint

This shows where the library appears, not that any named system is affected. Version, module and configuration determine that, and nothing below establishes them.

| Measure (2026-10-22) | Figure |
|---|---|
| GitHub repos declaring `hapi-fhir-base` | 2,254 |
| … `hapi-fhir-server` | 579 |
| … `hapi-fhir-jpaserver-base` | 570 |
| `hapiproject/hapi` Docker pulls since 2019-12 | 5,349,794 |
| deps.dev dependents of `hapi-fhir-base` 8.12.1 | 99 (57 indirect) |
| Global Atlas voluntary entries | 44 |

These count different things and do not sum. GitHub figures include forks; pulls are not installs; the Atlas is a directory, not a census. Downstream pins range from 5.7.9 (OpenMRS FHIR2) to 8.12.1 (Apache Camel).

**Commercial.** Smile CDR's changelog maps 2026.05.R01 → 8.10.0, 2026.05.R02 → 8.10.1, 2026.08.R02 → 8.12.1 and 2026.02.R03 → 8.8.2. Smile CDR has its own modules, so these mappings alone do not show that a given finding is reachable there; I did not test it. IEHP's [November 2025 board packet](https://www.iehp.org/content/dam/iehp-org/en/documents/governing-board/governing-board-meetings/2025/november-2025/November%2013%202025%20-%20IEHP%20Governing%20Board%20Meeting%20-%20Meeting%20Packet%20-%2011-13-2025.pdf) records a Smile CDR licence, and [Jefferson Health Plans' documentation](https://www.jeffersonhealthplans.com/home/about-us/interoperability/authentication-and-data-endpoints.html) names Smile CDR for its FHIR endpoint. A [2023 Smile announcement](https://smiledigitalhealth.com/our-blog/mihin-modernizes-fhirs-up-its-health-information-exchange) describes a MiHIN partnership; current status is unverified. CHPW's provider-directory API is served from a `smilecdr.com` host, per its [developer portal](https://medicare.chpw.org/contact-us/chpw-interoperability-developer-portal/). None of these sources gives a HAPI version.

**Public sector.** CMS's [BFD server](https://github.com/CMSgov/beneficiary-fhir-data), Blue Button's FHIR back end, extends HAPI's plain `RestfulServer` with its own data layer; it is not the HAPI JPA server. CMS DPC, AB2D and Germany's DEMIS components declare HAPI dependencies. These are source dependencies only.

## Fix status

As of 2026-10-22 — master `f2fce24162a`, `rel_9_0`, tags v8.8.2, v8.10.1, v8.12.1:

| Finding | Status |
|---|---|
| Partition override | Present; handler unchanged, no shipped entitlement policy |
| Gzip decompression | Present; `ServletRequestDetails.java` byte-identical at every ref |
| Conditional create | Fixed in `063b073e8c1`, on master and `rel_9_0` only |
| Subscription delivery | Present; no commits to either class |

The next release, 9.0.0, is scheduled for 2026-11-19. It is a breaking Spring Boot 4 / Jackson 3 / Hibernate 7 upgrade, with no 8.x backport. Commit `b5b0ae75978` (PR [#8404](https://github.com/hapifhir/hapi-fhir/pull/8404), issue [#8387](https://github.com/hapifhir/hapi-fhir/issues/8387)) extends `STORAGE_PARTITION_SELECTED` to requests without a resource type. It is unreleased, adds no entitlement policy, and leaves the extension handler unchanged.

The 2026 advisories for the sibling `org.hl7.fhir.core` library cover separate code and do not correspond to these findings.

## Mitigation

No released version fixes these. The entitlement control was exercised in tests; the rest are from source inspection.

- **Partition override:** register a `STORAGE_PARTITION_SELECTED` interceptor that checks the caller's entitlement to the final partition. Strip the `request-partition-ids` entry extension at the gateway.
- **Gzip:** `setUncompressIncomingContents(false)` where clients do not compress; otherwise enforce a decompressed-size limit ahead of HAPI.
- **Conditional create:** audit CREATE-without-READ grants, and suppress matched-resource bodies server-side. `Prefer: return=minimal` is caller-selected and is not a reliable control. A `ConsentInterceptor` can cover this path only if its policy is configured to.
- **Subscriptions:** restrict Subscription creation to administrators. Audit existing subscriptions for broad criteria and external endpoints. Egress blocking stops delivery to a blocked destination but does not add a read check.
- **Inventory:** find out whether purchased software contains HAPI FHIR, and which version and module.

## Disclosure

Coordinated through CERT/CC as **VU#394579**. The findings were confirmed on 2026-07-11/12 against `96ac50f89455`, each with a passing proof of concept. The conditional-create path was raised upstream as issue [#8253](https://github.com/hapifhir/hapi-fhir/issues/8253) on 2026-08-13 and fixed on 2026-08-19. Proof-of-concept sources will be published once released versions fix the remaining findings.

Findings were produced largely autonomously using the [Refute-or-Promote methodology](https://arxiv.org/pdf/2604.19049). I chose the target, reviewed each finding, wrote the proofs of concept and handled disclosure.

## References

- [HAPI FHIR](https://github.com/hapifhir/hapi-fhir) · [commit `96ac50f89455`](https://github.com/hapifhir/hapi-fhir/commit/96ac50f89455eb4cbef57fa858854e58b6dac4a5) · [FHIR R4 Subscription](https://hl7.org/fhir/R4/subscription.html)
- Upstream: [#8253](https://github.com/hapifhir/hapi-fhir/issues/8253) · [#8254](https://github.com/hapifhir/hapi-fhir/pull/8254) · [#8387](https://github.com/hapifhir/hapi-fhir/issues/8387) · [#8404](https://github.com/hapifhir/hapi-fhir/pull/8404)
- [Smile CDR changelog](https://smilecdr.com/docs/welcome/changelog.html) · [GitHub dependents](https://github.com/hapifhir/hapi-fhir/network/dependents) · [deps.dev](https://deps.dev/maven/ca.uhn.hapi.fhir%3Ahapi-fhir-base) · [Docker Hub](https://hub.docker.com/r/hapiproject/hapi)
- CWE [862](https://cwe.mitre.org/data/definitions/862.html) · [863](https://cwe.mitre.org/data/definitions/863.html) · [409](https://cwe.mitre.org/data/definitions/409.html)
