/*
 * Device-link harness: open mal_5ch_link.icc as a device-link profile
 * and create a transform using cmsCreateMultiprofileTransform.
 * This mirrors the canonical device-link code path in tificc/transicc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <lcms2.h>

int main(int argc, char **argv) {
    const char *prof_path = (argc > 1) ? argv[1] : "mal_5ch_link.icc";
    
    fprintf(stderr, "[dl_harness] Opening profile: %s\n", prof_path);
    fflush(stderr);
    
    /* Open the device-link profile */
    cmsHPROFILE hLink = cmsOpenProfileFromFile(prof_path, "r");
    if (!hLink) {
        fprintf(stderr, "[dl_harness] cmsOpenProfileFromFile failed\n");
        return 2;
    }
    fprintf(stderr, "[dl_harness] Profile opened OK\n");
    fflush(stderr);
    
    /* Check profile class */
    cmsProfileClassSignature cls = cmsGetDeviceClass(hLink);
    fprintf(stderr, "[dl_harness] Profile class: 0x%08x\n", (unsigned)cls);
    
    /* For device-link profiles, use cmsCreateMultiprofileTransform with 1 profile */
    /* Input format: 5-channel 8-bit, Output format: RGB 8-bit */
    cmsUInt32Number inFmt  = COLORSPACE_SH(PT_MCH5) | CHANNELS_SH(5) | BYTES_SH(1);
    cmsUInt32Number outFmt = TYPE_RGB_8;
    
    fprintf(stderr, "[dl_harness] inFmt=0x%08x outFmt=0x%08x\n", inFmt, outFmt);
    fprintf(stderr, "[dl_harness] Calling cmsCreateMultiprofileTransform...\n");
    fflush(stderr);
    
    cmsHTRANSFORM xf = cmsCreateMultiprofileTransform(
        &hLink, 1,
        inFmt, outFmt,
        INTENT_PERCEPTUAL, 0);
    
    if (!xf) {
        fprintf(stderr, "[dl_harness] Transform returned NULL (profile rejected)\n");
        cmsCloseProfile(hLink);
        return 3;
    }
    
    fprintf(stderr, "[dl_harness] Transform created! Calling cmsDoTransform...\n");
    fflush(stderr);
    
    unsigned char in[5]  = {0x80, 0x7F, 0x80, 0x80, 0x80};
    unsigned char out[3] = {0};
    cmsDoTransform(xf, in, out, 1);
    
    fprintf(stderr, "[dl_harness] Survived: out=%02x %02x %02x\n",
            out[0], out[1], out[2]);
    
    cmsDeleteTransform(xf);
    cmsCloseProfile(hLink);
    return 0;
}
