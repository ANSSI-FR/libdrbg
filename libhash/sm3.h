/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SM3_H__
#define __SM3_H__

#include "utils.h"

#define SM3_STATE_SIZE    8 /* in 32 bits word */
#define SM3_BLOCK_SIZE   64
#define SM3_DIGEST_SIZE  32
#define SM3_DIGEST_SIZE_BITS  256

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < SM3_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SM3_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < SM3_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SM3_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SM3_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SM3_BLOCK_SIZE
#endif

#define SM3_HASH_MAGIC ((uint64_t)(0x2947510312849204ULL))
#define SM3_HASH_CHECK_INITIALIZED(A, ret, err) \
        MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SM3_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed */
	uint64_t sm3_total;
	/* Internal state */
	uint32_t sm3_state[SM3_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t sm3_buffer[SM3_BLOCK_SIZE];
        /* Initialization magic value */
        uint64_t magic;
} sm3_context;

int sm3_init(sm3_context *ctx);
int sm3_update(sm3_context *ctx, const uint8_t *input, uint32_t ilen);
int sm3_final(sm3_context *ctx, uint8_t output[SM3_DIGEST_SIZE]);
int sm3_scattered(const uint8_t **inputs, const uint32_t *ilens,
		   uint8_t output[SM3_DIGEST_SIZE]);
int sm3(const uint8_t *input, uint32_t ilen, uint8_t output[SM3_DIGEST_SIZE]);

#endif /* __SM3_H__ */
