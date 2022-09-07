/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __BELT_HASH_H__
#define __BELT_HASH_H__

#include "utils.h"

/*
 * 32-bit integer manipulation macros
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n, b, i)                          \
do {                                                    \
        (n) =     ( ((uint32_t) (b)[(i) + 3]) << 24 )        \
                | ( ((uint32_t) (b)[(i) + 2]) << 16 )        \
                | ( ((uint32_t) (b)[(i) + 1]) <<  8 )        \
                | ( ((uint32_t) (b)[(i)    ])       );       \
} while( 0 )
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n, b, i)                  \
do {                                            \
        (b)[(i) + 3] = (uint8_t) ( (n) >> 24 );      \
        (b)[(i) + 2] = (uint8_t) ( (n) >> 16 );      \
        (b)[(i) + 1] = (uint8_t) ( (n) >>  8 );      \
        (b)[(i)    ] = (uint8_t) ( (n)       );      \
} while( 0 )
#endif

/*
 * 64-bit integer manipulation macros
 */
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n,b,i)                            \
do {                                                    \
    (n) = ( ((uint64_t) (b)[(i)    ]) << 56 )                \
        | ( ((uint64_t) (b)[(i) + 1]) << 48 )                \
        | ( ((uint64_t) (b)[(i) + 2]) << 40 )                \
        | ( ((uint64_t) (b)[(i) + 3]) << 32 )                \
        | ( ((uint64_t) (b)[(i) + 4]) << 24 )                \
        | ( ((uint64_t) (b)[(i) + 5]) << 16 )                \
        | ( ((uint64_t) (b)[(i) + 6]) <<  8 )                \
        | ( ((uint64_t) (b)[(i) + 7])            );          \
} while( 0 )
#endif /* GET_UINT64_BE */

#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n,b,i)            \
do {                                    \
    (b)[(i)    ] = (uint8_t) ( (n) >> 56 );  \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 48 );  \
    (b)[(i) + 2] = (uint8_t) ( (n) >> 40 );  \
    (b)[(i) + 3] = (uint8_t) ( (n) >> 32 );  \
    (b)[(i) + 4] = (uint8_t) ( (n) >> 24 );  \
    (b)[(i) + 5] = (uint8_t) ( (n) >> 16 );  \
    (b)[(i) + 6] = (uint8_t) ( (n) >>  8 );  \
    (b)[(i) + 7] = (uint8_t) ( (n)       );  \
} while( 0 )
#endif /* PUT_UINT64_BE */

#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n,b,i)                            \
do {                                                    \
    (n) = ( ((uint64_t) (b)[(i) + 7]) << 56 )                \
        | ( ((uint64_t) (b)[(i) + 6]) << 48 )                \
        | ( ((uint64_t) (b)[(i) + 5]) << 40 )                \
        | ( ((uint64_t) (b)[(i) + 4]) << 32 )                \
        | ( ((uint64_t) (b)[(i) + 3]) << 24 )                \
        | ( ((uint64_t) (b)[(i) + 2]) << 16 )                \
        | ( ((uint64_t) (b)[(i) + 1]) <<  8 )                \
        | ( ((uint64_t) (b)[(i)    ])            );          \
} while( 0 )
#endif /* GET_UINT64_LE */

#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n,b,i)            \
do {                                    \
    (b)[(i) + 7] = (uint8_t) ( (n) >> 56 );  \
    (b)[(i) + 6] = (uint8_t) ( (n) >> 48 );  \
    (b)[(i) + 5] = (uint8_t) ( (n) >> 40 );  \
    (b)[(i) + 4] = (uint8_t) ( (n) >> 32 );  \
    (b)[(i) + 3] = (uint8_t) ( (n) >> 24 );  \
    (b)[(i) + 2] = (uint8_t) ( (n) >> 16 );  \
    (b)[(i) + 1] = (uint8_t) ( (n) >>  8 );  \
    (b)[(i)    ] = (uint8_t) ( (n)       );  \
} while( 0 )
#endif /* PUT_UINT64_LE */


#define BELT_HASH_BLOCK_SIZE   32
#define BELT_HASH_DIGEST_SIZE  32
#define BELT_HASH_DIGEST_SIZE_BITS  256

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < BELT_HASH_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE BELT_HASH_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < BELT_HASH_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS BELT_HASH_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < BELT_HASH_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE BELT_HASH_BLOCK_SIZE
#endif

#define BELT_HASH_HASH_MAGIC ((uint64_t)(0x3278323b37829187ULL))
#define BELT_HASH_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == BELT_HASH_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed */
	uint64_t belt_hash_total;
	/* Internal state */
	uint8_t belt_hash_state[BELT_HASH_BLOCK_SIZE];
	/* Internal encryption data */
	uint8_t belt_hash_h[BELT_HASH_BLOCK_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t belt_hash_buffer[BELT_HASH_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} belt_hash_context;

#define BELT_BLOCK_LEN          16 /* The BELT encryption block length */
#define BELT_KEY_SCHED_LEN      32 /* The BELT key schedul length */

int belt_init(const uint8_t *k, uint32_t k_len, uint8_t ks[BELT_KEY_SCHED_LEN]);
void belt_encrypt(const uint8_t in[BELT_BLOCK_LEN], uint8_t out[BELT_BLOCK_LEN], const uint8_t ks[BELT_KEY_SCHED_LEN]);
void belt_decrypt(const uint8_t in[BELT_BLOCK_LEN], uint8_t out[BELT_BLOCK_LEN], const uint8_t ks[BELT_KEY_SCHED_LEN]);

int belt_hash_init(belt_hash_context *ctx);
int belt_hash_update(belt_hash_context *ctx, const uint8_t *input, uint32_t ilen);
int belt_hash_final(belt_hash_context *ctx, uint8_t output[BELT_HASH_DIGEST_SIZE]);
int belt_hash_scattered(const uint8_t **inputs, const uint32_t *ilens,
		     uint8_t output[BELT_HASH_DIGEST_SIZE]);
int belt_hash(const uint8_t *input, uint32_t ilen, uint8_t output[BELT_HASH_DIGEST_SIZE]);

#endif /* __BELT_HASH_H__ */
