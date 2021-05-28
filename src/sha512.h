#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>

#include "fixedint.h"

/* state */
typedef struct sha512_context_ {
    uint64_t  length, state[8];
    size_t curlen;
    unsigned char buf[128];
    int num_qwords;
} sha512_context;

#define SHA512_DIGEST_LENGTH 64

int sha512_init(sha512_context * md);
int sha512_final(sha512_context * md, unsigned char *out);
int sha512_update(sha512_context * md, const unsigned char *in, size_t inlen);
int sha512(const unsigned char *message, size_t message_len, unsigned char *out);

typedef sha512_context sha384_context;

#define SHA384_DIGEST_LENGTH 48

int sha384_init(sha384_context * md);
int sha384_final(sha384_context * md, unsigned char *out);
int sha384_update(sha384_context * md, const unsigned char *in, size_t inlen);
int sha384(const unsigned char *message, size_t message_len, unsigned char *out);

#endif
