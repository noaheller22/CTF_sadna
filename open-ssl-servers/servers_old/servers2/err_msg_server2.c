#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const unsigned char KEY[8] = "12345678";   /* 8-byte DES key   */
static const unsigned char IV [8] = "ABCDEFGH";   /* 8-byte DES IV    */

static void serve(int cli)
{
    uint16_t n;
    if (read(cli, &n, 2) != 2) return;
    n = ntohs(n);

    unsigned char ct[n], pt[n + 16];
    if (read(cli, ct, n) != n) return;

    ERR_clear_error();                 /* start with empty queue */

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len1 = 0, len2 = 0, ok = 1;

    EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, KEY, IV);
    ok &= EVP_DecryptUpdate(ctx, pt, &len1, ct, n);
    ok &= EVP_DecryptFinal_ex(ctx, pt + len1, &len2);   /* ← fails on bad pad */
    EVP_CIPHER_CTX_free(ctx);

    if (ok) {
        write(cli, "OK\n", 3);
    } else {
        unsigned long e = ERR_get_error();              /* first entry */
        char buf[120];
        ERR_error_string_n(e, buf, sizeof buf);
        strncat(buf, "\n", sizeof buf - strlen(buf) - 1);
        write(cli, buf, strlen(buf));
    }
}

int main(void)
{
    /* one-time OpenSSL initialisation */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET,
                             .sin_port   = htons(4444),
                             .sin_addr   = { htonl(INADDR_ANY) } };
    bind(s, (struct sockaddr *)&a, sizeof a);
    listen(s, 16);

    for (;;)
    {
        int c = accept(s, NULL, NULL);
        if (c >= 0) { serve(c); close(c); }
    }
}