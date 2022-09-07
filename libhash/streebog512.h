/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __STREEBOG512_H__
#define __STREEBOG512_H__

#include "utils.h"
#include "streebog.h"

#define STREEBOG512_BLOCK_SIZE   STREEBOG_BLOCK_SIZE
#define STREEBOG512_DIGEST_SIZE  64
#define STREEBOG512_DIGEST_SIZE_BITS  512

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE	0
#endif
#if (MAX_DIGEST_SIZE < STREEBOG512_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE STREEBOG512_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < STREEBOG512_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS STREEBOG512_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < STREEBOG512_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE STREEBOG512_BLOCK_SIZE
#endif

#define STREEBOG512_HASH_MAGIC ((uint64_t)(0x3293187509128364ULL))
#define STREEBOG512_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == STREEBOG512_HASH_MAGIC) && \
                  ((A)->streebog_digest_size == STREEBOG512_DIGEST_SIZE) && ((A)->streebog_block_size == STREEBOG512_BLOCK_SIZE), ret, err)

typedef streebog_context streebog512_context;

int streebog512_init(streebog512_context *ctx);
int streebog512_update(streebog512_context *ctx, const uint8_t *input, uint32_t ilen);
int streebog512_final(streebog512_context *ctx, uint8_t output[STREEBOG512_DIGEST_SIZE]);
int streebog512_scattered(const uint8_t **inputs, const uint32_t *ilens,
		      uint8_t output[STREEBOG512_DIGEST_SIZE]);
int streebog512(const uint8_t *input, uint32_t ilen, uint8_t output[STREEBOG512_DIGEST_SIZE]);

#endif /* __STREEBOG512_H__ */
