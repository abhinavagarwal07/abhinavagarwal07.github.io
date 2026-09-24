---
layout: post
title: "Four Security Findings in dcm4che and the dcm4chee Imaging Archive"
date: 2026-09-23 00:00:00 +0000
categories: [Security, Advisory]
tags: [dcm4che, dcm4chee, dicom, pacs, healthcare, denial-of-service]
description: "A storage-status operation that purged a synthetic image, two infinite-loop parser inputs, and costly multipart boundary scanning in dcm4che 5.34.3."
toc: true
---

## Summary

[dcm4chee-arc-light](https://github.com/dcm4che/dcm4chee-arc-light) is a medical-imaging archive built on [dcm4che](https://github.com/dcm4che/dcm4che). I reported four findings for which the project has now published GitHub Security Advisories. They affect storage administration or the parsing of image uploads:

| Finding | Public advisory | Demonstrated result |
|---|---|---|
| Storage-status mass deletion | [GHSA-v4gf-mj3c-fhgw](https://github.com/dcm4che/dcm4chee-arc-light/security/advisories/GHSA-v4gf-mj3c-fhgw) | One synthetic image purged from the official default archive image; retrieval returned `410 Gone` |
| JPEG parser infinite loop | [GHSA-f534-844q-pf2h](https://github.com/dcm4che/dcm4chee-arc-light/security/advisories/GHSA-f534-844q-pf2h) | A six-byte input held one library parser thread |
| MP4 parser infinite loop | [GHSA-gm72-f8wg-xpwv](https://github.com/dcm4che/dcm4chee-arc-light/security/advisories/GHSA-gm72-f8wg-xpwv) | A sixteen-byte input held one library parser thread |
| Multipart boundary CPU amplification | [GHSA-862w-384m-xgg8](https://github.com/dcm4che/dcm4chee-arc-light/security/advisories/GHSA-862w-384m-xgg8) | Four parse tasks delayed benign work about 46 seconds in a synthetic four-worker executor |

The archive test used the official `dcm4che/dcm4chee-arc-psql:5.34.3` image at digest `sha256:f127f5940971eeaa732a50d51d2f44435e6999639bf334d48382507d01921423`. The parser tests used 5.34.3 classes or JARs directly. All records were synthetic. Source review identified archive STOW-RS routes to the parsers, but I did not demonstrate a stock archive-wide outage from the parser inputs. The details below are sufficient to construct the test inputs without a published exploit repository.

## Storage status becomes physical deletion

The archive's [`StorageRS.changeStatus()`](https://github.com/dcm4che/dcm4chee-arc-light/blob/5.35.1/dcm4chee-arc-storage-rs/src/main/java/org/dcm4chee/arc/storage/rs/StorageRS.java#L185) updates all matching file-location records on a specified storage system. Changing locations from `OK` to `TO_DELETE` places them in the normal [`PurgeStorageScheduler`](https://github.com/dcm4che/dcm4chee-arc-light/blob/5.35.1/dcm4chee-arc-delete/src/main/java/org/dcm4chee/arc/delete/impl/PurgeStorageScheduler.java#L570) path, which unlinks the underlying files and removes the location records. This operation is scoped to a storage ID, not to an individual study or series.

To reproduce it on a disposable archive, ingest one synthetic DICOM object and confirm that QIDO-RS and WADO-RS can find and retrieve it. Query `GET /dcm4chee-arc/storage` to obtain a storage ID; the test image returned `fs1`. Then send a bodyless, unauthenticated `POST /dcm4chee-arc/storage/fs1/changestatus?from=OK&to=TO_DELETE` to the default image. The lab received `200 OK` with `{"count":1}`. The location first changed status while the image file remained; after the default purge scheduler ran, the file and location row were gone. QIDO-RS still listed the study as online, while WADO-RS retrieval returned `410 Gone`.

The tested default image required no login for the request. I purged one synthetic object; the source path shows that the status change targets all `OK` locations on the chosen storage system. I did not test a production archive.

## Six JPEG bytes keep a parser thread busy

The complete input is six bytes, in hexadecimal: `FF D8 FF E1 00 02`. It starts a JPEG and declares an APP1 segment, then ends. In the 5.34.3 [`JPEGParser` APP-segment loop](https://github.com/dcm4che/dcm4che/blob/5.34.3/dcm4che-imageio/src/main/java/org/dcm4che3/imageio/codec/jpeg/JPEGParser.java#L238), a short read at end-of-file is not treated as a terminal condition. The parser reuses buffer contents and makes no progress. A direct invocation of `JPEGParser` on these bytes kept one thread running until a watchdog stopped the process.

The archive route identified in the [advisory](https://github.com/dcm4che/dcm4chee-arc-light/security/advisories/GHSA-f534-844q-pf2h) is `POST /dcm4chee-arc/aets/{AETitle}/rs/studies` (STOW-RS). Send a `multipart/related` request with a DICOM JSON metadata part whose `PixelData` (tag `7FE00010`) has a `BulkDataURI` referencing a binary part. Label that part `Content-Type: image/jpeg` and make its body the six bytes above. Source routes the spooled part to `new JPEGParser(channel)` after STOW-RS role validation. My infinite-loop measurement was at library level; I did not establish how many such requests a stock archive would accept or whether they would exhaust the whole service.

## A zero-length extended MP4 box repeats forever

An MP4 box whose 32-bit size is `1` carries a 64-bit extended size. The sixteen-byte test file consists of `00 00 00 01`, the ASCII bytes `free`, and eight zero bytes. The `free` box type sends the 5.34.3 constructor into its search path. In [`MP4Parser.nextBox()`](https://github.com/dcm4che/dcm4che/blob/5.34.3/dcm4che-imageio/src/main/java/org/dcm4che3/imageio/codec/mp4/MP4Parser.java#L194-L208), the zero extended size makes `box.end` equal `box.start`; the search seeks back and parses the same box again. Direct parsing did not advance and held one thread.

For the archive route described in the [advisory](https://github.com/dcm4che/dcm4chee-arc-light/security/advisories/GHSA-gm72-f8wg-xpwv), use the same STOW-RS multipart and `PixelData` `BulkDataURI` structure, but label the sixteen-byte binary part `Content-Type: video/mp4`. Source then reaches `new MP4Parser(channel)` after role validation. The demonstrated infinite loop was a library result, not a measured outage of a stock archive.

## A long multipart boundary multiplies CPU work

In 5.34.3, [`MultipartInputStream.isBoundary()`](https://github.com/dcm4che/dcm4che/blob/5.34.3/dcm4che-mime/src/main/java/org/dcm4che3/mime/MultipartInputStream.java#L129-L147) shifts and compares a boundary-sized window for each candidate byte. Its `remaining()` path moves ahead only one byte when the body repeatedly matches the boundary's first byte. Thus body length `N` and boundary length `L` multiply the work, approximately O(N × L), subject to server header and body limits.

To construct the tested input, set a `multipart/related` request's header `boundary` parameter to 65,533 hyphens followed by `Z`. The parser prefixes `--`, making its effective boundary 65,535 hyphens plus `Z`. Stream about 1.8 MiB of ASCII hyphens as an unterminated preamble, with no matching delimiter or well-formed part. Each candidate matches the beginning but fails near the end, forcing another long comparison one byte later. At an effective 16 KiB boundary, 1, 2, and 4 MiB bodies used about 6, 12, and 24 CPU-seconds; with a 1 MiB body, 16, 32, and 64 KiB boundaries used about 6, 12, and 23 CPU-seconds. Four concurrent 1.8 MiB parse tasks delayed unrelated work by about 46 seconds in a synthetic four-worker executor. STOW-RS calls this parser after role validation, but I did not establish that stock WildFly accepted the same header and body sizes or suffered a whole-service outage.

## Fix and deployment status

The [JPEG change](https://github.com/dcm4che/dcm4che/commit/e1f3a208a1b76f79e7b912835cf914e0e6633557) makes truncated reads fail; the [MP4 change](https://github.com/dcm4che/dcm4che/commit/a19927e1b786112435dd8760426f8bceecb61fca) rejects the reported zero-progress box; and the [multipart change](https://github.com/dcm4che/dcm4che/commit/c114abc77051f02a7f3e9dca12c46816b593da1c) short-circuits the reported repeated-byte shape. The multipart change does not impose a general boundary-length cap.

The mass-deletion advisory labels `5.35.2` as patched. At the checked [archive source commit](https://github.com/dcm4che/dcm4chee-arc-light/blob/51d2b6717b58c22a6a95906a426fea5144a08478/dcm4chee-arc-storage-ejb/src/main/java/org/dcm4chee/arc/storage/ejb/StorageEJB.java#L471-L487), however, `StorageEJB.updateStatus()` still selects the unrestricted query for `OK` to `TO_DELETE`; the narrower orphan-only query is selected for other destination statuses. That is a source-level concern, not a runtime test of a newer image. Check the [archive releases](https://github.com/dcm4che/dcm4chee-arc-light/releases), [library releases](https://github.com/dcm4che/dcm4che/releases), and the four advisories for current build and remediation information.

At publication, the latest GitHub release in both source repositories was `5.35.1`; neither had published a `5.35.2` release tag. All four advisories listed no known CVE. Their version fields should not be read as evidence that a tested fixed image was available.

These tests do not establish exploitation at a hospital, an affected-hospital count, or clinical harm. Exposure depends on the deployed build and on which archive interfaces a site makes reachable. Independent backups matter especially for the storage-status issue.
