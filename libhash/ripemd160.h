/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __RIPEMD160_H__
#define __RIPEMD160_H__

#include "utils.h"

#define RIPEMD160_STATE_SIZE   5
#define RIPEMD160_BLOCK_SIZE   64
#define RIPEMD160_DIGEST_SIZE  20
#define RIPEMD160_DIGEST_SIZE_BITS  160

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < RIPEMD160_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE RIPEMD160_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS	0
#endif
#if (MAX_DIGEST_SIZE_BITS < RIPEMD160_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS RIPEMD160_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < RIPEMD160_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE RIPEMD160_BLOCK_SIZE
#endif

#define RIPEMD160_HASH_MAGIC ((uint64_t)(0x7392018463926719ULL))
#define RIPEMD160_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == RIPEMD160_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed */
	uint64_t ripemd160_total;
	/* Internal state */
	uint32_t ripemd160_state[RIPEMD160_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t ripemd160_buffer[RIPEMD160_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} ripemd160_context;

int ripemd160_init(ripemd160_context *ctx);
int ripemd160_update(ripemd160_context *ctx, const uint8_t *input, uint32_t ilen);
int ripemd160_final(ripemd160_context *ctx, uint8_t output[RIPEMD160_DIGEST_SIZE]);
int ripemd160_scattered(const uint8_t **inputs, const uint32_t *ilens,
		     uint8_t output[RIPEMD160_DIGEST_SIZE]);
int ripemd160(const uint8_t *input, uint32_t ilen, uint8_t output[RIPEMD160_DIGEST_SIZE]);

#endif /* __RIPEMD160_H__ */
