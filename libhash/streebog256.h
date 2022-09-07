/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __STREEBOG256_H__
#define __STREEBOG256_H__

#include "utils.h"
#include "streebog.h"

#define STREEBOG256_BLOCK_SIZE   STREEBOG_BLOCK_SIZE
#define STREEBOG256_DIGEST_SIZE  32
#define STREEBOG256_DIGEST_SIZE_BITS  256

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < STREEBOG256_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE STREEBOG256_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < STREEBOG256_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS STREEBOG256_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < STREEBOG256_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE STREEBOG256_BLOCK_SIZE
#endif

#define STREEBOG256_HASH_MAGIC ((uint64_t)(0x11221a2122328332ULL))
#define STREEBOG256_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == STREEBOG256_HASH_MAGIC) && \
		  ((A)->streebog_digest_size == STREEBOG256_DIGEST_SIZE) && ((A)->streebog_block_size == STREEBOG256_BLOCK_SIZE), ret, err)

typedef streebog_context streebog256_context;

int streebog256_init(streebog256_context *ctx);
int streebog256_update(streebog256_context *ctx, const uint8_t *input, uint32_t ilen);
int streebog256_final(streebog256_context *ctx, uint8_t output[STREEBOG256_DIGEST_SIZE]);
int streebog256_scattered(const uint8_t **inputs, const uint32_t *ilens,
			   uint8_t output[STREEBOG256_DIGEST_SIZE]);
int streebog256(const uint8_t *input, uint32_t ilen, uint8_t output[STREEBOG256_DIGEST_SIZE]);

#endif /* __STREEBOG256_H__ */
