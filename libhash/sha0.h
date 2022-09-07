/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA0_H__
#define __SHA0_H__

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
#define PUT_UINT32_LE(n, b, i)		  	\
do {					    	\
	(b)[(i) + 3] = (uint8_t) ( (n) >> 24 );      \
	(b)[(i) + 2] = (uint8_t) ( (n) >> 16 );      \
	(b)[(i) + 1] = (uint8_t) ( (n) >>  8 );      \
	(b)[(i)    ] = (uint8_t) ( (n)       );      \
} while( 0 )
#endif

/*
 * 64-bit integer manipulation macros
 */
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

#define SHA0_STATE_SIZE   5
#define SHA0_BLOCK_SIZE   64
#define SHA0_DIGEST_SIZE  20
#define SHA0_DIGEST_SIZE_BITS  160

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < SHA0_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA0_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < SHA0_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SHA0_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHA0_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA0_BLOCK_SIZE
#endif

#define SHA0_HASH_MAGIC ((uint64_t)(0x6611302537891263ULL))
#define SHA0_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA0_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed */
	uint64_t sha0_total;
	/* Internal state */
	uint32_t sha0_state[SHA0_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t sha0_buffer[SHA0_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} sha0_context;

/* Init hash function. Returns 0 on success, -1 on error. */
int sha0_init(sha0_context *ctx);

int sha0_update(sha0_context *ctx, const uint8_t *input, uint32_t ilen);

/* Finalize. Returns 0 on success, -1 on error.*/
int sha0_final(sha0_context *ctx, uint8_t output[SHA0_DIGEST_SIZE]);

/*
 * Scattered version performing init/update/finalize on a vector of buffers
 * 'inputs' with the length of each buffer passed via 'ilens'. The function
 * loops on pointers in 'inputs' until it finds a NULL pointer. The function
 * returns 0 on success, -1 on error.
 */
int sha0_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[SHA0_DIGEST_SIZE]);

/*
 * Single call version performing init/update/final on given input.
 * Returns 0 on success, -1 on error.
 */
int sha0(const uint8_t *input, uint32_t ilen, uint8_t output[SHA0_DIGEST_SIZE]);

#endif /* __SHA0_H__ */
