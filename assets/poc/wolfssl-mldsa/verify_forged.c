/*
 * verify_forged.c - companion verifier for poc_heap_forgery_v2.c
 *
 * Checks that the forged signature produced by the PoC passes
 * wc_dilithium_verify_msg() from the linked libwolfssl binary
 * (not an inlined copy of dilithium.c).
 *
 * Run poc_heap_forgery_v2 first — it writes poc_pk.bin, poc_sig.bin,
 * poc_msg.bin to the current directory.
 *
 * Build (from the wolfssl source root, e.g. wolfssl-5.9.0/):
 *   gcc -O2 -I. -include wolfssl/options.h claudy/verify_forged.c \
 *     -L./src/.libs -lwolfssl -o /tmp/verify_forged
 *
 * On macOS add: -framework CoreFoundation -framework Security
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define EXPECTED_PK_SZ  1312
#define EXPECTED_SIG_SZ 2420

static int read_file(const char *path, unsigned char *buf, int maxsz)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    int n = (int)fread(buf, 1, maxsz, f);
    /* check nothing was left unread */
    if (fgetc(f) != EOF) { fclose(f); return -2; }
    fclose(f);
    return n;
}

int main(void)
{
    static unsigned char pk[EXPECTED_PK_SZ], sig[EXPECTED_SIG_SZ], msg[4096];
    int pklen, siglen, msglen, ret, ok = 0;
    dilithium_key vk;

    pklen  = read_file("poc_pk.bin",  pk,  sizeof(pk));
    siglen = read_file("poc_sig.bin", sig, sizeof(sig));
    msglen = read_file("poc_msg.bin", msg, sizeof(msg));

    if (pklen != EXPECTED_PK_SZ) {
        fprintf(stderr, "poc_pk.bin: expected %d bytes, got %d\n",
                EXPECTED_PK_SZ, pklen);
        return 1;
    }
    if (siglen != EXPECTED_SIG_SZ) {
        fprintf(stderr, "poc_sig.bin: expected %d bytes, got %d\n",
                EXPECTED_SIG_SZ, siglen);
        return 1;
    }
    if (msglen <= 0 || msglen == -2) {
        fprintf(stderr, "poc_msg.bin: bad or truncated (%d)\n", msglen);
        return 1;
    }

    printf("pk: %d bytes, sig: %d bytes, msg: %d bytes\n", pklen, siglen, msglen);

    ret = wc_dilithium_init(&vk);
    if (ret) { fprintf(stderr, "init: %d\n", ret); return 1; }
    ret = wc_dilithium_set_level(&vk, WC_ML_DSA_44);
    if (ret) { fprintf(stderr, "level: %d\n", ret); return 1; }
    ret = wc_dilithium_import_public(pk, (word32)pklen, &vk);
    if (ret) { fprintf(stderr, "import: %d\n", ret); return 1; }

    ret = wc_dilithium_verify_msg(sig, (word32)siglen, msg, (word32)msglen, &ok, &vk);
    wc_dilithium_free(&vk);

    if (ret != 0 || ok != 1) {
        printf("REJECTED (ret=%d ok=%d)\n", ret, ok);
        return 1;
    }
    printf("VERIFIED - linked libwolfssl accepted the forged signature\n");
    return 0;
}
