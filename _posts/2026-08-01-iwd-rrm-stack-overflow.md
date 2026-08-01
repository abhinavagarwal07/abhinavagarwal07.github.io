---
layout: post
title: "No Password, No Association, No Fix: Four Bugs in the Wi-Fi Daemon SteamOS Ships by Default"
date: 2026-08-01 00:00:00 +0000
categories: [Security, Advisory]
tags: [iwd, wifi, 802-11, 802-11k, 802-11r, rrm, fast-bss-transition, linux, steamos, cwe-121, cwe-125, cwe-191, cwe-697, stack-overflow]
description: "A nearby attacker can knock a Linux machine off Wi-Fi with one spoofed frame — no password, no association. iwd writes 31 bytes per visible access point into a 512-byte stack buffer and never checks; seventeen APs in range overflows it. SteamOS ships iwd as its default backend, where the impact is a crash rather than code execution. Reported in May, confirmed, patches sent. Still unfixed."
toc: true
pin: true
---

## Summary

[iwd](https://git.kernel.org/pub/scm/network/wireless/iwd.git/) is the Wi-Fi supplicant from the
Linux wireless project — the alternative to `wpa_supplicant`, packaged by every major distro and
used as the default backend on SteamOS.

I found four defects in it. The one that matters is a stack buffer overflow in the 802.11k Radio
Resource Measurement handler. iwd answers a neighbour-report request by writing one 31-byte record
per visible access point into a 512-byte stack buffer, with no bounds check. Sixteen fit. A normal
office has more than sixteen APs in range.

| # | Bug | Location | Class | Reachable from |
|---|-----|----------|-------|----------------|
| 1 | RRM beacon report stack overflow | `src/rrm.c:334`, `:370` | Stack buffer overflow ([CWE-121](https://cwe.mitre.org/data/definitions/121.html)) | Spoofed action frame, connected, no PMF needed |
| 2 | HE Capabilities validator reads the wrong byte | `src/ie.c:2714` | OOB read ([CWE-125](https://cwe.mitre.org/data/definitions/125.html)) | Passive scan, pre-association |
| 3 | `mde_equal()` compares its first argument to itself | `src/ft.c:385` | Broken check ([CWE-697](https://cwe.mitre.org/data/definitions/697.html)) | 802.11r FT auth response |
| 4 | FTE sub-element length underflows a `uint8_t` | `src/ie.c:1919` | Integer underflow → OOB read ([CWE-191](https://cwe.mitre.org/data/definitions/191.html)) | 802.11r FT auth response, before any MIC |

> **Affected:** all four coexist in **1.30 through 3.12**, the latest release. They arrived
> separately — the FTE parser in 0.1, RRM in 1.1, `mde_equal()` in 1.14, and the HE validator in
> 1.30 — so older versions have a subset.
> **Fixed in:** nothing. As I write this, upstream `master` is still `d003d0e5` ("Release 3.12",
> 13 March 2026) and there is no tag after 3.12.

> **PoC code, patches and sanitizer logs:**
> **[github.com/abhinavagarwal07/iwd-security-poc](https://github.com/abhinavagarwal07/iwd-security-poc)**

No CVE IDs. Intel's bounty program closed the submission as out of scope; the maintainers confirmed
the findings but haven't requested identifiers. So the findings are numbered, not named.

---

## Why I'm publishing without a fix

I reported to the maintainers on 19 May and sent patches on 21 May. They confirmed all four on
28 May — 65 days ago. A maintainer has since reviewed the patches, verified them against the spec,
and applied them locally: *"From my side these patches look good. I've applied/verified them
against the spec."*

So the fixes exist, they're correct, and a maintainer says so. They're just not upstream. `master`
is still `d003d0e5` with no commits since 13 March, no release, and no advisory.

On 21 July I said I'd publish by 27 July. This is a few days later than that.

I don't think finding 1 is safe to sit on quietly. It fires from a spoofed frame in an ordinary RF
environment, and the trigger condition — seventeen visible APs — is not something an operator can
reason about without knowing the bug exists. Someone running iwd on an embedded image right now has
no way to find out they should care.

The [previous post]({% post_url 2026-07-30-open62541-pubsub-transfersubscriptions-cves %}) was the
opposite case: maintainers fixed it in four days and asked me to withhold the PoC, so I did. The
difference isn't my policy. It's whether there's a fix to point people at.

---

## Who runs iwd

Packaged by Arch, Fedora, Debian, Ubuntu, Gentoo, NixOS, Yocto/OpenEmbedded (`meta-oe`, recipe
`iwd_3.12.bb`) and Buildroot. On desktop distros it's an available NetworkManager backend, not the
default — and all of them build with a stack protector, so finding 1 there is a repeatable Wi-Fi
outage rather than code execution.

The interesting cases are elsewhere.

**SteamOS** is the largest consumer fleet I found with iwd as the OS default rather than an option —
`steamos-customizations-git` ships `/etc/NetworkManager/conf.d/wifi_backend.conf` containing
`wifi.backend=iwd`. The version isn't 3.12: the newest `holo-main` package is iwd 3.9-1.2, and the
older `holo-3.7` repository tops out at 3.0-1. All four defects are present in upstream 3.9, and
Valve's PKGBUILD patches are BSS-cache only.

Finding 1 on a Deck is a crash, not code execution — I pulled the 3.9-1.2 package and checked: the
binary is PIE and imports `__stack_chk_fail`, so the stack protector aborts. (PIE alone wouldn't
stop it; the canary does.) Valve PSIRT notified 29 June. Footprint, not a victim list — I did not
test a Deck.

**Embedded images** built through Yocto or Buildroot are where the hardening story changes.
Stack protector, PIE and FORTIFY are per-image configuration choices there, and the architectures
involved have no CET. I found no official OpenWrt iwd package, so iwd on OpenWrt would be a custom
build.

---

## Finding 1: the RRM beacon report overflow

802.11k lets an AP ask a station "what other APs can you see?". It's how enterprise networks steer
clients between access points. iwd answers by building a Radio Measurement Report action frame:

```c
static bool rrm_report_beacon_results(struct rrm_state *rrm,
                                        struct l_queue *bss_list)
{
        uint8_t frame[512];                          /* rrm.c:334 */
        uint8_t *ptr = frame;

        *ptr++ = 0x05;                               /* Category: Radio Measurement */
        *ptr++ = 0x01;                               /* Action: Radio Measurement Report */
        *ptr++ = beacon->info.dialog_token;

        for (entry = l_queue_get_entries(bss_list); entry; entry = entry->next) {
                struct scan_bss *bss = entry->data;
                uint8_t report[257];
                size_t report_len;

                /* three filters, all bypassable — see below */

                report_len = build_report_for_bss(beacon, bss, report);
                rrm_build_measurement_report(&beacon->info, report, report_len, ptr);

                ptr += report_len + 5;               /* rrm.c:370 */
        }

        return rrm_send_response(rrm, frame, ptr - frame);
}
```

`build_report_for_bss()` returns `sizeof(struct rrm_beacon_report)` — a packed struct of
1+1+8+2+1+1+1+6+1+4 = 26 bytes. `rrm_build_measurement_report()` writes a 5-byte Measurement Report
IE header in front of it. So 31 bytes per access point, and `ptr` advances by 31 with nothing
checking it against the end of `frame`.

```
usable space      = 512 - 3         = 509
records that fit  = floor(509 / 31) = 16
record #17 writes   frame[499..529] → 18 bytes past the end
each further AP     +31 bytes
```

The list being iterated is `station_get_bss_list()` — the station's own scan cache. So the count
isn't something the attacker supplies in the request. It's a property of the room. Seventeen
neighbouring APs is an apartment block, an office floor, an airport. An attacker who wants
determinism rather than luck just beacons the extra ones in.

Both call sites overflow: `rrm_handle_beacon_table()` (rrm.c:390, cached results) and
`rrm_scan_results()` (rrm.c:407, fresh scan).

### Getting the request accepted

```c
if (station_get_state(rrm->station) != STATION_STATE_CONNECTED ||
                rrm->pending)
        return;                                      /* rrm.c:727 */

bss = station_get_connected_bss(rrm->station);

if (memcmp(bss->addr, mpdu->address_2, 6))           /* rrm.c:733 */
        return;
```

That's the whole access control: the station has to be connected, and the frame's source address
has to equal the connected AP's MAC. No management frame protection requirement anywhere on this
path.

On WPA2 without 802.11w, `address_2` is a field the attacker fills in. Nothing authenticates it.

Then three filters inside the loop skip non-matching BSSes, and one request clears all three:

| Filter | Where | Bypass |
|--------|-------|--------|
| BSSID match | rrm.c:348 | wildcard BSSID `ff:ff:ff:ff:ff:ff` — `util_is_broadcast_address()` sets `wildcard`, the memcmp is skipped |
| SSID match | rrm.c:352 | omit the SSID sub-element, so `beacon->has_ssid` stays false |
| channel range | rrm.c:362 | `bss_in_request_range()` returns true unconditionally when `beacon->channel == 0`, and `rrm_verify_beacon_request()` (rrm.c:474) only enforces channel/operating-class for non-TABLE modes |

So the request is: category 5, action 0, measurement type 5 (Beacon), mode TABLE, channel 0,
wildcard BSSID, no SSID sub-element. Every cached BSS gets a record.

Worth noting the shape of that third bypass. TABLE mode is *meant* to skip the channel restriction —
"just tell me what you already have cached" is the whole point of it. The check that would have
caught a channel of 0 is deliberately disabled for the one mode that reads straight from the cache.

### What the attacker controls in the overflow

Per 31-byte record:

| Offset | Bytes | Field | Comes from |
|---|---|---|---|
| +2 | 1 | measurement token | the request |
| +4 | 1 | measurement type | the request |
| +5 | 1 | operating class | the request |
| +6 | 1 | channel | a beacon the attacker sends |
| +7 | 8 | `scan_start_time` | **zero in TABLE mode** |
| +15 | 2 | duration | the request |
| +20 | 6 | BSSID | a beacon the attacker sends |
| +27 | 4 | parent TSF | a beacon the attacker sends |

Those eight zero bytes at +7 are the interesting part.

### x86-64 is a dead end, and it's a coincidence

On the x86-64 build I disassembled, the frame is:

```
frame[520..527] = saved rbx
frame[528..535] = saved rbp
frame[536..543] = saved r12
frame[544..551] = saved r13
frame[552..559] = saved r14
frame[560..567] = saved r15
frame[568..575] = saved RIP
```

Record #18 starts at `frame[3 + 17*31]` = `frame[530]`. Record #19 starts at `frame[561]`, and
`frame[561 + 7]` = `frame[568]`.

`scan_start_time` — eight bytes, zero in TABLE mode — lands exactly on the eight-byte saved return
address. Not approximately. Exactly.

So on x86-64 the overflow zeroes the return address instead of choosing it. Reliable crash, no
control. Active-scan mode makes `scan_start_time` a real timestamp rather than zero, but a
timestamp isn't a chosen value either.

There's a lesson in that which cuts against the finding: the record stride happening to be
congruent with the register save area is luck, and luck that goes the other way on a different
compiler or a different iwd version. I'm reporting the alignment I measured on the binary I had,
not a property of the bug.

### ARM32 is not a dead end

On ARM32 with a typical prologue for this function — `push {r4-r10, lr}` then `sub sp, #524` — the
saved `lr` sits at `frame[552..555]`. That is `bssid[2..5]` of record #18. Four attacker-chosen
bytes straight into `pc` on the epilogue's `ldmia.w sp!, {..., pc}`.

I built that: the vulnerable write loop lifted verbatim into a wrapper reproducing that frame
layout, cross-compiled for armhf with `-fno-stack-protector -fno-pie`, run under `qemu-arm-static`.

```
[*] win() at 0x00010735
[*] BSS#18 MAC set to de:ad:35:07:01:00
[*] Triggering overflow with 20 BSSes...

*** RCE ACHIEVED — IWD rrm_report_beacon_results LR hijack ***
[*] Proof file written: /tmp/pwned

Exit code: 42
```

**Be precise about what that shows.** It demonstrates that the write primitive reaches the saved
return address on that ABI, with attacker-chosen bytes. It is not an exploit against a specific
shipped binary. Which record number and which field land on `lr` depend on the target build's
register allocation — something an attacker reads off the binary, and something I did not do for
any real device.

### The real daemon

The standalone harnesses prove the arithmetic. This proves the path.

Three `mac80211_hwsim` radios: hostapd on one, iwd 3.12 built with AddressSanitizer on another,
monitor mode on the third. Inject 25 fake beacons to fill the scan cache, then send the Radio
Measurement Request as a real 802.11 action frame via `NL80211_CMD_FRAME` — the same call hostapd
makes to talk to a station.

```
==67193==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffe8136a2a0
WRITE of size 26 at 0x7ffe8136a2a0 thread T0
    #0 in __interceptor_memcpy
    #1 in memcpy                       string_fortified.h:29
    #2 in rrm_build_measurement_report  src/rrm.c:244
    #3 in rrm_report_beacon_results     src/rrm.c:367
    #4 in rrm_handle_beacon_table       src/rrm.c:390
    #5 in rrm_handle_beacon_request     src/rrm.c:641
    #6 in rrm_frame_watch_cb            src/rrm.c:775
    #7 in frame_watch_unicast_notify    src/frame-xchg.c:234
    ...
    #15 in main                         src/main.c:610

Address 0x7ffe8136a2a0 is located in stack of thread T0 at offset 896 in frame
    #0 in rrm_report_beacon_results src/rrm.c:328

  This frame has 2 object(s):
    [48, 305) 'report' (line 344)
    [384, 896) 'frame' (line 334) <== Memory access at offset 896 overflows this variable
```

Real daemon, real frame, unmodified 3.12 source. The full trace, the dmesg log and the packet
capture are in the [PoC repo](https://github.com/abhinavagarwal07/iwd-security-poc/tree/main/01-rrm-stack-overflow/poc/evidence).

One honest caveat about the lab: the request came from the AP's own radio, because that was the
convenient way to send it. That's not the security boundary. The boundary is the `memcmp` at
rrm.c:733, and any adjacent radio satisfies it by setting `address_2` on a network without PMF.

### FORTIFY_SOURCE doesn't catch this

Worth spelling out, because a 512-byte stack buffer overflowed by `memcpy` looks exactly like the
thing FORTIFY_SOURCE exists to catch.

It doesn't, on any distro. Each individual `memcpy` writes 26 bytes and is perfectly in bounds. The
overflow is the *loop* accumulating them. `rrm_build_measurement_report()` receives `to` as a bare
`uint8_t *` and the compiler has no idea how far it is from the end of `frame`. There is no single
call site where the check would have anything to compare.

### Fix

```c
 	uint8_t frame[512];
+	const uint8_t *frame_end = frame + sizeof(frame);
 	uint8_t *ptr = frame;
 ...
 		report_len = build_report_for_bss(beacon, bss, report);
 
+		if ((size_t)(frame_end - ptr) < report_len + 5)
+			break;
+
 		rrm_build_measurement_report(&beacon->info, report,
 						report_len, ptr);
```

Truncating is correct behaviour here, not a compromise — 802.11k lets a station report a subset,
and a station with more neighbours than fit in one frame has to truncate regardless.

---

## Finding 2: the validator and the consumer read different bytes

The HE Capabilities element body is 6 octets of MAC Capabilities followed by 11 octets of PHY
Capabilities. Channel Width Set is bits B1–B7 of PHY Capabilities byte 0 — body offset **6**
(802.11ax-2021 §9.4.2.248.3).

The validator reads offset 7:

```c
bool ie_validate_he_capabilities(const void *data, size_t len)
{
        const uint8_t *ptr = data;

        if (len < 22)
                return false;

        width_set = bit_field((ptr + 7)[0], 1, 7);      /* ie.c:2714 */
        ...
        if (width_160   && (!width_40_80 || freq_2_4 || len < 26))
                return false;
        if (width_80p80 && (!width_160   || freq_2_4 || len < 30))
                return false;
```

The consumer reads offset 6:

```c
width_set = bit_field(he_cap->he_phy_capa[0], 1, 7) &
            bit_field((hec + 6)[0], 1, 7);              /* band.c:631 */
```

Both are handed the same pointer — `wiphy.c:1086` validates `iter.data`, `wiphy.c:1099` passes that
same `iter.data` to the estimator.

So the length guards are keyed on a byte that has nothing to do with which MCS maps get read. Set
`hec[6] = 0x1C` and `hec[7] = 0x00`: the validator sees a width set of zero and waves through a
22-byte element, and the estimator sees B1, B2 and B3 set and walks the 160 MHz and 80+80 maps.

```c
tx_map = hec + 19;                                      /* band.c:637 */

if (test_bit(&width_set, 3))                            /* 80+80  */
        find_rate_he(rx_map + 8, tx_map + 8, ...);      /* hec[27], hec[28] */
if (test_bit(&width_set, 2))                            /* 160    */
        find_rate_he(rx_map + 4, tx_map + 4, ...);      /* hec[23], hec[24] */
```

`find_best_mcs_nss()` reads `tx_map[0]` and `tx_map[1]`. On a 22-byte body — valid indices 0 to 21 —
that's offsets 23–24, and 27–28 on the deeper path.

```
==99081==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000001be8
READ of size 1 at 0x603000001be8 thread T0
    #0 in find_best_mcs_nss        he_caps_oob.c:135
    #1 in find_rate_he             he_caps_oob.c:175
    #2 in band_estimate_he_rx_rate he_caps_oob.c:256

0x603000001be8 is located 2 bytes after 22-byte region [0x603000001bd0,0x603000001be6)
```

Same result under gcc 11.4 on Linux/x86-64 and clang 16 on macOS/arm64.

One precondition, stated honestly: the width set is ANDed with the *local* adapter's PHY
capabilities, so the machine has to advertise 160 MHz or 80+80 for the corresponding branch to run.
Wi-Fi 6 client adapters commonly do.

### The bytes aren't random, which is the actual finding

In a real beacon the elements sit contiguously in one buffer. `iter.data` points into the middle of
it, so the bytes past the HE Capabilities body are the *next element*:

```
...[EID=255][Len=23][ExtID=35][ 22-byte HE Caps body ][EID][Len][body...]...
                              ^hec[0]                  ^22  ^23  ^24
```

`hec[23]` is the next element's length byte. `hec[24]` is its first body byte. A rogue AP picks
those by choosing what element to put after HE Capabilities.

So this isn't really "leak two heap bytes". It's: **choose the data rate iwd computes for your AP.**
That estimate feeds iwd's BSS ranking, which decides what the station prefers.

To be precise about what has to be malformed: the HE Capabilities element does. A 22-byte body that
claims 160 MHz and 80+80 support while omitting the MCS maps those widths require is not a legal
element — that contradiction is the bug. What does *not* have to be malformed is anything after it.
Three ordinary standards-compliant trailing elements — SSID, DS Parameter Set, a vendor element —
produce three different estimated rates, so the attacker steers the number with entirely legitimate
content and only one crafted element to get there.

Every HE Capabilities element seen during scanning reaches this validation path — before
association, with no credentials and no user interaction. It's the crafted width/length
inconsistency that turns that into the OOB read; ordinary beacons pass through it harmlessly.

The fix is one character: `(ptr + 7)` → `(ptr + 6)`.

---

## Finding 3: `memcmp(mde1, mde1, ...)`

```c
static bool mde_equal(const uint8_t *mde1, const uint8_t *mde2)
{
        if (!mde1 || !mde2)
                return false;

        /*
         * Check for an MD IE identical to the one we sent in message 1
         * ...
         */
        return memcmp(mde1, mde1, mde1[1] + 2) == 0;    /* ft.c:385 */
}
```

`memcmp(x, x, n)` is always zero. `mde2` is never read. The function returns true for any two
non-NULL pointers.

Its only caller is `ft_parse_ies()` at ft.c:667, on the 802.11r FT Authentication Response path
(`__ft_rx_authenticate`) and the FT-over-DS action response path (`__ft_rx_action`). During a roam
the target AP is meant to echo back the Mobility Domain element the station sent. That check does
not happen.

**This is not an authentication bypass**, and I want to be clear about that because a broken
`memcmp` in an 802.11r path invites the assumption that it is. The reassociation stage does the
comparison correctly:

```c
/* An MD IE identical to the one we sent must be present */
if (sent_mde && (!mde || memcmp(sent_mde, mde, sent_mde[1] + 2)))
        return -EBADMSG;                                /* ft.c:496 */
```

and the FTE MIC there is keyed on PMK-R1, which a rogue AP doesn't have.

What the broken check actually costs you: a response carrying an arbitrary mobility domain ID and
arbitrary FT capability flags passes the *authentication* stage instead of being rejected there, so
the station carries on into FTE parsing and key derivation for a mobility domain it never agreed to.

Which matters mostly because of what's on that path one call later.

One trap if you're patching this yourself: changing the second `mde1` to `mde2` looks like the
whole job and breaks FT roaming. The arguments have different shapes. `mde1` is `info->mde`, a raw
3-byte payload (`uint8_t mde[3]`, `ft.c:54`); `mde2` comes back from `parse_ies()` as
`ie_tlv_iter_get_data(&iter) - 2`, a full IE with tag and length. They disagree at byte 0, so a
direct `memcmp` always mismatches and every FT authentication response gets rejected. `mde1[1]`
isn't a length either — with no IE header it's the MDID high byte. What works is validating
`mde2[1] == 3` and comparing the payloads:

```c
return mde2[1] == 3 && memcmp(mde1, mde2 + 2, 3) == 0;
```

---

## Finding 4: the FTE sub-element walker

```c
        uint8_t len, subelem_id, subelem_len;

        len = ie_tlv_iter_get_length(iter);
        ...
        len  -= 66 + mic_len;
        data += 66 + mic_len;

        while (len >= 2) {
                subelem_id  = *data++;
                subelem_len = *data++;

                switch (subelem_id) {
                case 1:
                        if (subelem_len != 6)
                                return -EINVAL;

                        memcpy(info->r1khid, data, 6);
                        ...
                }

                data += subelem_len;
                len  -= subelem_len + 2;                /* ie.c:1919 */
        }
```

`subelem_len` is never checked against the bytes actually remaining. Two things follow.

The `case` handlers validate only the *declared* length — `== 6` for R1KH-ID, `35..51` for the GTK
sub-element, `1..48` for R0KH-ID, `== 33` for IGTK. With `len == 2` and a declared 6-byte R1KH-ID,
zero bytes remain and six get read.

And `len -= subelem_len + 2` on a `uint8_t` wraps instead of going negative: `2 - 8` is 250, and
`while (len >= 2)` keeps going, walking `data` further past the element each iteration.

```
Subelem id=1  declared_len=20  available=5   <-- needs 22, has 5
  uint8_t underflow: 5 - 22 = 239

  len   subelem_len+2   uint8 result   loop continues?
  5     22              239            yes, out of bounds
  3     12              247            yes, out of bounds
  2     3               255            yes, out of bounds
  10    11              255            yes, out of bounds
  15    15              0              no
```

Termination is a random walk mod 256 driven by out-of-bounds bytes — around 128 iterations on
average, advancing up to 257 bytes each. Comfortably far enough to leave the frame allocation.

The declared-length checks do bound every *write* into the fixed-size `ie_ft_info` fields, so
there's no out-of-bounds write here. The reads are unbounded.

### It runs before anything cryptographic

```c
static bool ft_parse_fte(struct handshake_state *hs, const uint8_t *snonce,
                                const uint8_t *fte, struct ie_ft_info *ft_info)
{
        if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
                                        kck_len, ft_info) < 0)      /* ft.c:353 */
                return false;

        if (ft_info->mic_element_count != 0 ||
                        memcmp(ft_info->mic, zeros, kck_len))       /* ft.c:357 */
                return false;
```

Parse first, check second. And this is the FT Authentication Response path, where the FTE carries
no MIC at all — the code requires `mic_element_count == 0` and an all-zero MIC field. There is
nothing between a rogue AP's response and the parser.

The reassociation path has the same ordering: parse at ft.c:513, `ft_calculate_fte_mic()` at
ft.c:524.

To reach it you need the station to attempt an FT roam to a BSS you control — same SSID, matching
mobility domain, and either a natural roam or a deauth to force one. Finding 3 removes the mobility
domain check on that same path.

The fix is three lines, before the switch:

```c
+               if (subelem_len > len - 2)
+                       return -EINVAL;
```

`len >= 2` is the loop condition, so `len - 2` can't underflow there.

---

## Proof of concept

**[github.com/abhinavagarwal07/iwd-security-poc](https://github.com/abhinavagarwal07/iwd-security-poc)**

Four standalone harnesses. Each lifts the vulnerable function verbatim out of iwd, so they build
and run anywhere with a C compiler — no Wi-Fi hardware, no VM, no kernel modules.

```bash
git clone https://github.com/abhinavagarwal07/iwd-security-poc
cd iwd-security-poc

(cd 01-rrm-stack-overflow/poc    && ./run_poc.sh)   # ASan + no-canary + canary builds
(cd 02-he-caps-oob-read/poc      && ./run_poc.sh)   # heap OOB read
(cd 03-ft-mde-equal/poc          && ./run_poc.sh)   # broken comparison
(cd 04-fte-subelem-underflow/poc && ./run_poc.sh)   # uint8_t underflow
```

Also in the repo:

- **`01-rrm-stack-overflow/e2e/`** — the `mac80211_hwsim` harness that produced the real-daemon ASan
  crash, including the `NL80211_CMD_FRAME` sender and the packet capture.
- **`01-rrm-stack-overflow/arm32-rce/`** — the ARM32 variant. Cross-compile, run under QEMU, exit
  code 42.
- **`01-rrm-stack-overflow/rop_analysis.md`** — per-architecture frame layouts, including the
  x86-64 dead end worked out in full.
- **[`patches/`](https://github.com/abhinavagarwal07/iwd-security-poc/tree/main/patches)** — the
  four-patch `git format-patch` series as sent upstream on 21 May, commit messages intact, and
  reviewed and spec-verified by a maintainer. `git am patches/*.patch` against `d003d0e5`.
  Independent of each other, so a subset works.

Run it in a disposable VM. Several harnesses are expected to abort partway through — that's the
result, not a build failure.

---

## What to do

No fixed release exists, so: apply the [patch series](https://github.com/abhinavagarwal07/iwd-security-poc/tree/main/patches), or build with
`-fstack-protector-strong`, which turns finding 1 into an abort on the architectures where control
flow is otherwise reachable. Check the flags on your image, not your build host. On a Steam Deck,
`steamos-wifi-set-backend wpa_supplicant`.

PMF helps but doesn't close it. It makes the `address_2` check at rrm.c:733 unspoofable, which
removes the drive-by trigger — but the buffer is still unbounded, and an AP the station is actually
associated to can send a *protected* Radio Measurement Request that sails through. That covers a
hostile or compromised AP, and any rogue AP the station has been convinced to join.

The pattern in finding 1 is worth grepping for elsewhere: a loop appending fixed-size records into a
fixed-size buffer, where the record count comes from somewhere the author assumed was bounded. No
individual `memcpy` looks wrong, so FORTIFY_SOURCE and a call-site review both miss it.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-05-12 | Reported to Intel via Intigriti. |
| 2026-05-19 | Reported to the iwd maintainers. |
| 2026-05-21 | Patches sent for all four findings. |
| 2026-05-22 | Intigriti closed the submission as out of scope. |
| 2026-05-28 | Maintainers confirmed all four findings. |
| 2026-06-29 | Valve PSIRT notified — SteamOS ships iwd as the default backend. |
| 2026-07-21 | Told the maintainers I would publish by 27 July. |
| 2026-08-01 | This post and the PoC repo. Still no fix upstream. |

---

## Credit

All four findings are mine. Reported to the iwd maintainers on 19 May 2026 and confirmed on 28 May.
No CVE IDs have been assigned.

---

## References

- Upstream: [git.kernel.org/pub/scm/network/wireless/iwd.git](https://git.kernel.org/pub/scm/network/wireless/iwd.git/)
- PoC and patches: [github.com/abhinavagarwal07/iwd-security-poc](https://github.com/abhinavagarwal07/iwd-security-poc)
- [CWE-121](https://cwe.mitre.org/data/definitions/121.html) ·
  [CWE-125](https://cwe.mitre.org/data/definitions/125.html) ·
  [CWE-191](https://cwe.mitre.org/data/definitions/191.html) ·
  [CWE-697](https://cwe.mitre.org/data/definitions/697.html)
- IEEE 802.11-2020 §9.4.2.21 (Measurement Request/Report), §9.6.6 (Radio Measurement action frames)
- IEEE 802.11ax-2021 §9.4.2.248.3 (HE PHY Capabilities Information)
- Prior post, for the contrast in disclosure outcomes:
  [open62541]({% post_url 2026-07-30-open62541-pubsub-transfersubscriptions-cves %})
