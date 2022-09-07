/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __GOSTR34_11_94_H__
#define __GOSTR34_11_94_H__

#include "utils.h"

/****************************************************/
/*
 * 32-bit integer manipulation macros
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)				\
do {							\
	(n) =     ( ((uint32_t) (b)[(i)    ]) << 24 )	\
		| ( ((uint32_t) (b)[(i) + 1]) << 16 )	\
		| ( ((uint32_t) (b)[(i) + 2]) <<  8 )	\
		| ( ((uint32_t) (b)[(i) + 3])       );  \
} while( 0 )
#endif
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n, b, i)				\
do {							\
	(n) =     ( ((uint32_t) (b)[(i) + 3]) << 24 )	\
		| ( ((uint32_t) (b)[(i) + 2]) << 16 )	\
		| ( ((uint32_t) (b)[(i) + 1]) <<  8 )	\
		| ( ((uint32_t) (b)[(i)    ])       );  \
} while( 0 )
#endif


#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)			\
do {						\
	(b)[(i)    ] = (uint8_t) ( (n) >> 24 );      \
	(b)[(i) + 1] = (uint8_t) ( (n) >> 16 );      \
	(b)[(i) + 2] = (uint8_t) ( (n) >>  8 );      \
	(b)[(i) + 3] = (uint8_t) ( (n)       );      \
} while( 0 )
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n, b, i)			\
do {						\
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

#define GOSTR34_11_94_STATE_SIZE   4
#define GOSTR34_11_94_BLOCK_SIZE   32
#define GOSTR34_11_94_DIGEST_SIZE  32
#define GOSTR34_11_94_DIGEST_SIZE_BITS  256

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < GOSTR34_11_94_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE GOSTR34_11_94_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < GOSTR34_11_94_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS GOSTR34_11_94_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < GOSTR34_11_94_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE GOSTR34_11_94_BLOCK_SIZE
#endif

#define GOSTR34_11_94_HASH_MAGIC ((uint64_t)(0x1262734139734143ULL))
#define GOSTR34_11_94_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == GOSTR34_11_94_HASH_MAGIC), ret, err)

#define ROTL_GOSTR34_11_94(x, n)      ((((uint32_t)(x)) << (n)) | (((uint32_t)(x)) >> (32-(n))))

/* All the inner operations */

typedef enum {
	GOST34_11_94_NORM   = 0,
	GOST34_11_94_RFC4357 = 1,
} gostr34_11_94_type;

typedef struct {
	/* "Type" of GOST, changing the SBOX to use */
	gostr34_11_94_type gostr34_11_94_t;
	/* Number of bytes processed */
	uint64_t gostr34_11_94_total;
	/* Internal state: 4 64-bit values */
	uint64_t gostr34_11_94_state[GOSTR34_11_94_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t gostr34_11_94_buffer[GOSTR34_11_94_BLOCK_SIZE];
	/* The sum */
	uint64_t gostr34_11_94_sum[GOSTR34_11_94_STATE_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} gostr34_11_94_context;


/* Init hash function. Returns 0 on success, -1 on error. */
int gostr34_11_94_init(gostr34_11_94_context *ctx);

/* Function to modify the initial IV as it is not imposed by the RFCs */
int gostr34_11_94_set_iv(gostr34_11_94_context *ctx, const uint64_t iv[GOSTR34_11_94_STATE_SIZE]);

/* Function to modify the GOST type (that will dictate the underlying SBOX to use for block encryption) */
int gostr34_11_94_set_type(gostr34_11_94_context *ctx, gostr34_11_94_type type);

int gostr34_11_94_update(gostr34_11_94_context *ctx, const uint8_t *input, uint32_t ilen);

/* Finalize. Returns 0 on success, -1 on error.*/
int gostr34_11_94_final(gostr34_11_94_context *ctx, uint8_t output[GOSTR34_11_94_DIGEST_SIZE]);

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int gostr34_11_94_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[GOSTR34_11_94_DIGEST_SIZE], gostr34_11_94_type type);

int gostr34_11_94_scattered_norm(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[GOSTR34_11_94_DIGEST_SIZE]);

int gostr34_11_94_scattered_rfc4357(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[GOSTR34_11_94_DIGEST_SIZE]);

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int gostr34_11_94(const uint8_t *input, uint32_t ilen, uint8_t output[GOSTR34_11_94_DIGEST_SIZE], gostr34_11_94_type type);

int gostr34_11_94_norm(const uint8_t *input, uint32_t ilen, uint8_t output[GOSTR34_11_94_DIGEST_SIZE]);

int gostr34_11_94_rfc4357(const uint8_t *input, uint32_t ilen, uint8_t output[GOSTR34_11_94_DIGEST_SIZE]);

#endif /* __GOSTR34_11_94_H__ */
