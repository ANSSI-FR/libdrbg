/*
 *  Copyright (C) 2022 - This file is part of libdrbg project
 *
 *  Author:       Ryad BENADJILA <ryad.benadjila@ssi.gouv.fr>
 *  Contributor:  Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */

#ifndef __SHA384_H__
#define __SHA384_H__

#include "utils.h"
#include "sha2.h"

#define SHA384_STATE_SIZE   8
#define SHA384_BLOCK_SIZE   128
#define SHA384_DIGEST_SIZE  48
#define SHA384_DIGEST_SIZE_BITS  384

/* Compute max hash digest and block sizes */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE 0
#endif
#if (MAX_DIGEST_SIZE < SHA384_DIGEST_SIZE)
#undef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA384_DIGEST_SIZE
#endif

#ifndef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS    0
#endif
#if (MAX_DIGEST_SIZE_BITS < SHA384_DIGEST_SIZE_BITS)
#undef MAX_DIGEST_SIZE_BITS
#define MAX_DIGEST_SIZE_BITS SHA384_DIGEST_SIZE_BITS
#endif

#ifndef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE  0
#endif
#if (MAX_BLOCK_SIZE < SHA384_BLOCK_SIZE)
#undef MAX_BLOCK_SIZE
#define MAX_BLOCK_SIZE SHA384_BLOCK_SIZE
#endif

#define SHA384_HASH_MAGIC ((uint64_t)(0x9227239b32098412ULL))
#define SHA384_HASH_CHECK_INITIALIZED(A, ret, err) \
	MUST_HAVE((((void *)(A)) != NULL) && ((A)->magic == SHA384_HASH_MAGIC), ret, err)

typedef struct {
	/* Number of bytes processed on 128 bits */
	uint64_t sha384_total[2];
	/* Internal state */
	uint64_t sha384_state[SHA384_STATE_SIZE];
	/* Internal buffer to handle updates in a block */
	uint8_t sha384_buffer[SHA384_BLOCK_SIZE];
	/* Initialization magic value */
	uint64_t magic;
} sha384_context;

int sha384_init(sha384_context *ctx);
int sha384_update(sha384_context *ctx, const uint8_t *input, uint32_t ilen);
int sha384_final(sha384_context *ctx, uint8_t output[SHA384_DIGEST_SIZE]);
int sha384_scattered(const uint8_t **inputs, const uint32_t *ilens,
		     uint8_t output[SHA384_DIGEST_SIZE]);
int sha384(const uint8_t *input, uint32_t ilen, uint8_t output[SHA384_DIGEST_SIZE]);

#endif /* __SHA384_H__ */
