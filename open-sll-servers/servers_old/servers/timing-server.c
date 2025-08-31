/*  gcc timing_oracle.c -o timing_oracle -lssl -lcrypto
 *
 *  Listens on TCP 4445.
 *  Protocol identical to err_oracle.
 *  Reply is **always** "OK\n".
 *  Clients must distinguish padding via network-side timing.
 */
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static const unsigned char KEY[16] = "0123456789abcdef";
static const unsigned char IV [16] = "abcdef0123456789";

static void serve(int cli)
{
    uint16_t n;
    if (read(cli, &n, 2) != 2) return;
    n = ntohs(n);

    unsigned char ct[n], pt[n + 16];
    if (read(cli, ct, n) != n) return;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len1 = 0, len2 = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, KEY, IV);
    EVP_DecryptUpdate(ctx, pt, &len1, ct, n);
    EVP_DecryptFinal_ex(ctx, pt + len1, &len2);   /* ignore success/fail */
    EVP_CIPHER_CTX_free(ctx);

    /* always send the same string */
    write(cli, "OK\n", 3);
}

int main(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET,
                             .sin_port   = htons(4445),
                             .sin_addr   = { htonl(INADDR_ANY) } };
    bind(s, (struct sockaddr *)&a, sizeof a);
    listen(s, 16);

    for (;;)
    {
        int c = accept(s, NULL, NULL);
        if (c >= 0) { serve(c); close(c); }
    }
}
